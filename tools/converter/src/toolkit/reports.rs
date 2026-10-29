use super::{cache, device, json, option, root, write_json, Result};
use serde_json::{json as j, Value};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};
fn number(v: &Value) -> Result<u64> {
    if let Some(n) = v.as_u64() {
        Ok(n)
    } else {
        let s = v.as_str().ok_or("missing numeric field")?;
        if let Some(h) = s.strip_prefix("0x") {
            u64::from_str_radix(h, 16).map_err(|e| e.to_string())
        } else {
            s.parse::<u64>().map_err(|e| e.to_string())
        }
    }
}
fn image(c: &harmonios_runtime::cache::CacheSet, a: u64) -> Result<Value> {
    for i in &c.images {
        if i.address > a {
            continue;
        }
        let m = cache::image(c, i.address)?;
        for s in m.segments {
            if s.name == "__TEXT" && a >= s.address && a < s.address + s.size {
                return Ok(j!({"path":i.path,"address":i.address}));
            }
        }
        for s in m.sections {
            if a >= s.address && a < s.address + s.size {
                return Ok(
                    j!({"path":i.path,"address":i.address,"segment":s.segment,"section":s.name}),
                );
            }
        }
    }
    Ok(Value::Null)
}
pub fn fault(path: &Path) -> Result<Value> {
    let d = json(path)?;
    let b = &d["dyldBootstrap"];
    let scene_fault = b["signal"] == 0 && b["scene"]["faulted"] == true;
    let (pc, base, fault, signal) = if scene_fault {
        let base = number(&b["cacheBase"])?;
        let pc = number(&b["scene"]["faultPc"])?;
        (
            pc.checked_sub(base).ok_or("scene fault precedes cache")?,
            base,
            pc,
            b["scene"]["signal"].clone(),
        )
    } else {
        let detail = b["detail"].as_str().ok_or("missing dyld detail")?;
        let tail = detail
            .split_once("PC cache+0x")
            .ok_or("report has no cache PC")?
            .1;
        let digits: String = tail.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        let pc = u64::from_str_radix(&digits, 16).map_err(|e| e.to_string())?;
        let runtime = number(&b["faultPc"])?;
        let base = runtime.checked_sub(pc).ok_or("invalid cache slide")?;
        let fault = number(&b["faultAddress"])?;
        (pc, base, fault, b["signal"].clone())
    };
    let c = cache::load(&root().join("artifacts/ios27-system/cache/dyld_shared_cache_arm64e"))?;
    let p = json(&root().join("artifacts/ios27-aot/package.json"))?;
    let pi = image(&c, c.preferred_base + pc)?;
    let address = if fault >= base {
        c.preferred_base + fault - base
    } else {
        0
    };
    let fi = if address > 0 {
        image(&c, address)?
    } else {
        Value::Null
    };
    let offset = fault.checked_sub(base);
    let selected = offset.is_some_and(|off| {
        p["ranges"].as_array().is_some_and(|v| {
            v.iter().any(|r| {
                r["offset"]
                    .as_u64()
                    .zip(r["size"].as_u64())
                    .is_some_and(|(a, n)| a <= off && off < a + n)
            })
        })
    });
    Ok(
        j!({"scope":if scene_fault {"scene"}else{"main"},"sceneStage":b["scene"]["stage"],"status":b["status"],"traps":b["traps"],"signal":signal,"cacheBase":format!("{base:#x}"),"pcOffset":format!("{pc:#x}"),"pcImage":pi["path"],"faultAddress":format!("{address:#x}"),"faultCacheOffset":offset.map(|n|format!("{n:#x}")),"faultPage":offset.map(|n|format!("{:#x}",n&!0x3fff)),"faultImage":fi["path"],"faultSegment":fi["segment"],"faultSection":fi["section"],"selectedInPackage":selected}),
    )
}
pub fn workqueue(path: &Path) -> Result<Value> {
    let d = json(path)?;
    let msg = d["dyldBootstrap"]["message"].as_str().unwrap_or("");
    let mut events = vec![];
    for t in msg.split("[scene=").skip(1) {
        let Some((t, _)) = t.split_once(']') else {
            continue;
        };
        let Some((prefix, words)) = t.split_once("words=") else {
            continue;
        };
        let mut raw = vec![];
        for w in words.split_whitespace() {
            let Some(w) = w.strip_prefix("0x") else {
                continue;
            };
            if let Ok(n) = u64::from_str_radix(w, 16) {
                raw.extend(n.to_le_bytes())
            }
        }
        if raw.len() != 72 {
            continue;
        }
        let u32 = |p| cache::u32le(&raw, p).unwrap();
        let u64 = |p| cache::u64le(&raw, p).unwrap();
        let filter = i16::from_le_bytes(raw[8..10].try_into().unwrap());
        let flags = u16::from_le_bytes(raw[10..12].try_into().unwrap());
        let ext = (0..4)
            .map(|i| format!("{:#x}", u64(40 + i * 8)))
            .collect::<Vec<_>>();
        events.push(j!({"scene":prefix.starts_with('1'),"workloop":prefix.split_once("wl=").and_then(|(_,s)|s.split_whitespace().next()),"syscallFlags":prefix.split_once("flags=").and_then(|(_,s)|s.split_whitespace().next()),"ident":format!("{:#x}",u64(0)),"filter":filter,"flags":format!("{flags:#x}"),"qos":format!("{:#x}",u32(12)),"udata":format!("{:#x}",u64(16)),"fflags":format!("{:#x}",u32(24)),"xflags":format!("{:#x}",u32(28)),"data":u64(32)as i64,"ext":ext,"threadRequest":filter == -17&&u32(24)&1!=0}));
    }
    let dropped = msg
        .split_once("guest kevent changes dropped=")
        .and_then(|(_, s)| s.split_whitespace().next())
        .and_then(|s| s.parse::<u64>().ok());
    Ok(
        j!({"threadRequests":events.iter().filter(|v|v["threadRequest"]==true).count(),"events":events,"dropped":dropped}),
    )
}
pub fn repeat(a: &[String]) -> Result<()> {
    let n = option(a, "--runs")
        .unwrap_or("3")
        .parse::<usize>()
        .map_err(|e| e.to_string())?;
    if !(1..=100).contains(&n) {
        return Err("runs must be between 1 and 100".into());
    }
    let out = option(a, "--output")
        .map(PathBuf::from)
        .unwrap_or_else(|| root().join("artifacts/repeat-acceptance"));
    let mut runs = vec![];
    let mut issues = vec![];
    for i in 1..=n {
        let dir = out.join(format!("run-{i:02}"));
        let mut args = vec![
            "--skip-build".into(),
            "--skip-install".into(),
            "--output".into(),
            dir.to_string_lossy().into_owned(),
        ];
        for k in ["--device", "--bundle", "--ability", "--timeout"] {
            if let Some(v) = option(a, k) {
                args.extend([k.into(), v.into()]);
            }
        }
        let start = Instant::now();
        let result = device::execute(&args, false);
        let report = json(&dir.join("device-compat-report.json")).unwrap_or(Value::Null);
        if let Err(e) = &result {
            issues.push(format!("Run {i}: {e}"))
        }
        if report["frameDiagnostics"]["recentFrames"]
            .as_array()
            .and_then(|v| v.first())
            .is_some_and(|r| r["sequenceNumber"] != 1)
        {
            issues.push(format!("Run {i}: first frame does not start at 1"))
        }
        if !dir.join("harmonios-latest.jpeg").is_file() {
            issues.push(format!("Run {i}: screenshot missing"))
        }
        runs.push(j!({"iteration":i,"elapsedSeconds":start.elapsed().as_secs_f64(),"report":report,"error":result.err()}));
    }
    let result = j!({"passed":issues.is_empty(),"issues":issues,"runs":runs});
    write_json(&out.join("acceptance-summary.json"), &result)?;
    if result["passed"] != true {
        return Err("repeat acceptance failed; see acceptance-summary.json".into());
    }
    Ok(())
}
