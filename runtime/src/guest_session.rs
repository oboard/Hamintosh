//! Host/guest session state for input, display geometry, and captured traces.
//!
//! This module deliberately stops at platform-neutral state transitions. The
//! host supplies real frame pixels through [`HostApi`]; no Darwin or iOS frame
//! is synthesized here. Input arrival and input delivery are separate: any host
//! thread may enqueue an event, but only the identified guest main thread may
//! drain the queue after the scene is ready.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

const TAB_BAR_HEIGHT_PT: f64 = 49.0;

/// Platform primitives used by a guest session.
///
/// Implementations may use a fake clock in tests. Presentation accepts pixels
/// produced elsewhere; this trait does not implement or emulate Apple rendering.
pub trait HostApi {
    fn now_ns(&mut self) -> u64;
    fn log(&mut self, message: &str);
    fn present_frame(&mut self, frame: Frame<'_>);
    fn wait_until(&mut self, deadline_ns: u64);
}

/// A real frame supplied to the host presentation boundary.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    pub pixels: &'a [u8],
    pub width: u32,
    pub height: u32,
    pub stride_bytes: usize,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Size {
    pub width: f64,
    pub height: f64,
}

impl Size {
    pub const fn new(width: f64, height: f64) -> Self {
        Self { width, height }
    }

    fn is_valid(self) -> bool {
        self.width.is_finite() && self.height.is_finite() && self.width > 0.0 && self.height > 0.0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub const fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Insets {
    pub top: f64,
    pub left: f64,
    pub bottom: f64,
    pub right: f64,
}

impl Insets {
    pub const ZERO: Self = Self {
        top: 0.0,
        left: 0.0,
        bottom: 0.0,
        right: 0.0,
    };
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Rect {
    pub origin: Point,
    pub size: Size,
}

impl Rect {
    pub fn max_x(self) -> f64 {
        self.origin.x + self.size.width
    }

    pub fn max_y(self) -> f64 {
        self.origin.y + self.size.height
    }
}

/// Rotation from the native host viewport into the guest's logical coordinate
/// space. Landscape sizes therefore normally have swapped width and height.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Orientation {
    #[default]
    Portrait,
    PortraitUpsideDown,
    LandscapeLeft,
    LandscapeRight,
}

/// Geometry for one orientation of the display.
///
/// `physical_px` and `host_vp` use the native, unrotated host orientation.
/// `guest_pt` and `safe_insets` use the current, oriented guest coordinate
/// space. Keeping all three sizes avoids assuming that host scale and guest
/// point scale are identical.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DisplayMetrics {
    pub physical_px: Size,
    pub host_vp: Size,
    pub guest_pt: Size,
    pub orientation: Orientation,
    pub safe_insets: Insets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayError {
    InvalidSize,
    InvalidSafeInsets,
}

impl fmt::Display for DisplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize => f.write_str("display sizes must be finite and positive"),
            Self::InvalidSafeInsets => {
                f.write_str("safe insets must be finite, nonnegative, and fit the guest")
            }
        }
    }
}

impl Error for DisplayError {}

impl DisplayMetrics {
    pub fn validate(&self) -> Result<(), DisplayError> {
        if !self.physical_px.is_valid() || !self.host_vp.is_valid() || !self.guest_pt.is_valid() {
            return Err(DisplayError::InvalidSize);
        }
        let insets = self.safe_insets;
        let values = [insets.top, insets.left, insets.bottom, insets.right];
        if values
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0)
            || insets.left + insets.right > self.guest_pt.width
            || insets.top + insets.bottom > self.guest_pt.height
        {
            return Err(DisplayError::InvalidSafeInsets);
        }
        Ok(())
    }

    pub fn host_to_physical(&self, point: Point) -> Point {
        Point {
            x: point.x * self.physical_px.width / self.host_vp.width,
            y: point.y * self.physical_px.height / self.host_vp.height,
        }
    }

    pub fn physical_to_host(&self, point: Point) -> Point {
        Point {
            x: point.x * self.host_vp.width / self.physical_px.width,
            y: point.y * self.host_vp.height / self.physical_px.height,
        }
    }

    /// Convert a host viewport position to oriented guest points.
    ///
    /// Coordinates are not clamped, so off-screen capture and cancellation can
    /// be represented and the forward/inverse transforms remain true inverses.
    pub fn host_to_guest(&self, point: Point) -> Point {
        let physical = self.host_to_physical(point);
        let u = physical.x / self.physical_px.width;
        let v = physical.y / self.physical_px.height;
        let (u, v) = match self.orientation {
            Orientation::Portrait => (u, v),
            Orientation::PortraitUpsideDown => (1.0 - u, 1.0 - v),
            Orientation::LandscapeLeft => (1.0 - v, u),
            Orientation::LandscapeRight => (v, 1.0 - u),
        };
        Point {
            x: u * self.guest_pt.width,
            y: v * self.guest_pt.height,
        }
    }

    /// Convert oriented guest points back to the native host viewport.
    pub fn guest_to_host(&self, point: Point) -> Point {
        let u = point.x / self.guest_pt.width;
        let v = point.y / self.guest_pt.height;
        let (u, v) = match self.orientation {
            Orientation::Portrait => (u, v),
            Orientation::PortraitUpsideDown => (1.0 - u, 1.0 - v),
            Orientation::LandscapeLeft => (v, 1.0 - u),
            Orientation::LandscapeRight => (1.0 - v, u),
        };
        self.physical_to_host(Point {
            x: u * self.physical_px.width,
            y: v * self.physical_px.height,
        })
    }

    /// The usable guest rectangle after applying oriented guest safe insets.
    pub fn guest_safe_area(&self) -> Rect {
        Rect {
            origin: Point {
                x: self.safe_insets.left,
                y: self.safe_insets.top,
            },
            size: Size {
                width: self.guest_pt.width - self.safe_insets.left - self.safe_insets.right,
                height: self.guest_pt.height - self.safe_insets.top - self.safe_insets.bottom,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputPhase {
    #[default]
    Begin,
    Move,
    End,
}

/// One input sample in host viewport coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct InputEvent {
    pub pointer_id: u64,
    pub phase: InputPhase,
    pub timestamp_ns: u64,
    pub position: Point,
    pub pressure: f64,
    pub cancelled: bool,
}

impl InputEvent {
    pub fn new(pointer_id: u64, phase: InputPhase, timestamp_ns: u64, position: Point) -> Self {
        Self {
            pointer_id,
            phase,
            timestamp_ns,
            position,
            pressure: 1.0,
            cancelled: false,
        }
    }

    pub fn cancel(pointer_id: u64, timestamp_ns: u64, position: Point) -> Self {
        Self {
            pointer_id,
            phase: InputPhase::Move,
            timestamp_ns,
            position,
            pressure: 0.0,
            cancelled: true,
        }
    }
}

/// Identity of the executable and OS artifacts to which a trace belongs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetIdentity {
    pub bundle_id: String,
    pub executable_sha256: [u8; 32],
    pub cache_uuid: [u8; 16],
    pub os_version: String,
}

impl TargetIdentity {
    pub fn new(
        bundle_id: impl Into<String>,
        executable_sha256: [u8; 32],
        cache_uuid: [u8; 16],
        os_version: impl Into<String>,
    ) -> Self {
        Self {
            bundle_id: bundle_id.into(),
            executable_sha256,
            cache_uuid,
            os_version: os_version.into(),
        }
    }
}

/// A captured host-input trace. Geometry and target identity travel with the
/// events so a trace cannot silently replay against a different display or app.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputTrace {
    pub target: TargetIdentity,
    pub metrics: DisplayMetrics,
    pub events: Vec<InputEvent>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThreadId(pub u64);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lifecycle {
    #[default]
    Launching,
    SceneReady,
    Active,
    Inactive,
    Terminated,
}

/// State for a touch sequence that has begun but has not ended or cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PointerState {
    pub pointer_id: u64,
    pub phase: InputPhase,
    pub timestamp_ns: u64,
    pub position: Point,
    pub pressure: f64,
    pub down_tab: Option<usize>,
}

/// Guest-main state that remains pending between input samples.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PendingState {
    pub active_pointers: BTreeMap<u64, PointerState>,
}

impl PendingState {
    pub fn pointer(&self, pointer_id: u64) -> Option<&PointerState> {
        self.active_pointers.get(&pointer_id)
    }

    pub fn is_active(&self, pointer_id: u64) -> bool {
        self.active_pointers.contains_key(&pointer_id)
    }
}

/// An event delivered on guest main, including its converted guest position.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DeliveredInput {
    pub pointer_id: u64,
    pub phase: InputPhase,
    pub timestamp_ns: u64,
    pub host_position: Point,
    pub position: Point,
    pub pressure: f64,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    WrongThread,
    InvalidTransition,
    TargetMismatch,
    DisplayMismatch,
    Terminated,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongThread => f.write_str("operation requires the guest main thread"),
            Self::InvalidTransition => f.write_str("invalid guest lifecycle transition"),
            Self::TargetMismatch => f.write_str("trace target does not match the session"),
            Self::DisplayMismatch => f.write_str("trace display does not match the session"),
            Self::Terminated => f.write_str("guest session is terminated"),
        }
    }
}

impl Error for SessionError {}

/// Core guest session. The queue is mutex-protected because host input may
/// arrive on a different thread; all other input state is mutated only by
/// `pump_guest_main`/`replay` on the identified guest main thread.
pub struct GuestSession<H: HostApi> {
    pub target: TargetIdentity,
    pub metrics: DisplayMetrics,
    pub main_thread: ThreadId,
    pub pending: PendingState,
    pub selected_tab: Option<usize>,
    pub lifecycle: Lifecycle,
    tab_count: usize,
    queue: Mutex<VecDeque<InputEvent>>,
    delivered: Vec<DeliveredInput>,
    host: H,
}

impl<H: HostApi> GuestSession<H> {
    pub fn new(
        target: TargetIdentity,
        metrics: DisplayMetrics,
        main_thread: ThreadId,
        tab_count: usize,
        host: H,
    ) -> Self {
        Self {
            target,
            metrics,
            main_thread,
            pending: PendingState::default(),
            selected_tab: None,
            lifecycle: Lifecycle::Launching,
            tab_count,
            queue: Mutex::new(VecDeque::new()),
            delivered: Vec::new(),
            host,
        }
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    pub fn into_host(self) -> H {
        self.host
    }

    pub fn tab_count(&self) -> usize {
        self.tab_count
    }

    pub fn delivered(&self) -> &[DeliveredInput] {
        &self.delivered
    }

    pub fn pending_event_count(&self) -> usize {
        self.lock_queue().len()
    }

    pub fn queued_events(&self) -> Vec<InputEvent> {
        self.lock_queue().iter().copied().collect()
    }

    /// Enqueue host input without processing it on the calling thread.
    pub fn queue_input(&self, event: InputEvent) -> Result<(), SessionError> {
        if self.lifecycle == Lifecycle::Terminated {
            return Err(SessionError::Terminated);
        }
        self.lock_queue().push_back(event);
        Ok(())
    }

    pub fn mark_scene_ready(&mut self, thread: ThreadId) -> Result<(), SessionError> {
        self.ensure_main(thread)?;
        match self.lifecycle {
            Lifecycle::Launching => {
                let now = self.host.now_ns();
                self.host.log(&format!(
                    "guest scene ready at {now} ns; input delivery enabled"
                ));
                self.lifecycle = Lifecycle::SceneReady;
                Ok(())
            }
            Lifecycle::SceneReady | Lifecycle::Active => Ok(()),
            Lifecycle::Inactive | Lifecycle::Terminated => Err(SessionError::InvalidTransition),
        }
    }

    pub fn activate(&mut self, thread: ThreadId) -> Result<(), SessionError> {
        self.ensure_main(thread)?;
        match self.lifecycle {
            Lifecycle::SceneReady | Lifecycle::Inactive => {
                self.lifecycle = Lifecycle::Active;
                Ok(())
            }
            Lifecycle::Active => Ok(()),
            Lifecycle::Launching | Lifecycle::Terminated => Err(SessionError::InvalidTransition),
        }
    }

    pub fn deactivate(&mut self, thread: ThreadId) -> Result<(), SessionError> {
        self.ensure_main(thread)?;
        match self.lifecycle {
            Lifecycle::Active | Lifecycle::SceneReady => {
                self.lifecycle = Lifecycle::Inactive;
                // Losing the scene also loses pointer capture. No synthetic
                // input event is inserted into either the live or replay trace.
                self.pending.active_pointers.clear();
                Ok(())
            }
            Lifecycle::Inactive => Ok(()),
            Lifecycle::Launching | Lifecycle::Terminated => Err(SessionError::InvalidTransition),
        }
    }

    pub fn terminate(&mut self, thread: ThreadId) -> Result<(), SessionError> {
        self.ensure_main(thread)?;
        if self.lifecycle == Lifecycle::Terminated {
            return Ok(());
        }
        self.lifecycle = Lifecycle::Terminated;
        self.pending.active_pointers.clear();
        self.lock_queue().clear();
        Ok(())
    }

    /// Drain queued input in FIFO order on guest main. Before scene readiness,
    /// or while inactive, events remain queued for a later pump.
    pub fn pump_guest_main(&mut self, thread: ThreadId) -> Result<usize, SessionError> {
        self.ensure_main(thread)?;
        self.drain_queue(false)
    }

    /// Replay a captured trace through the same queue and guest-main input path
    /// as live events. Timestamp waits are delegated to the host clock.
    pub fn replay(&mut self, trace: &InputTrace, thread: ThreadId) -> Result<usize, SessionError> {
        self.ensure_main(thread)?;
        if trace.target != self.target {
            return Err(SessionError::TargetMismatch);
        }
        if trace.metrics != self.metrics {
            return Err(SessionError::DisplayMismatch);
        }
        for event in &trace.events {
            self.queue_input(*event)?;
        }
        self.drain_queue(true)
    }

    /// Forward real pixels to the platform without creating substitute content.
    pub fn present_frame(&mut self, frame: Frame<'_>) {
        self.host.present_frame(frame);
    }

    /// Hit-test the guest tab bar in oriented guest points. The 49 pt interactive
    /// row sits above the bottom safe inset and uses the horizontally safe area.
    pub fn tab_at_guest_point(&self, point: Point) -> Option<usize> {
        if self.tab_count == 0 {
            return None;
        }
        let safe = self.metrics.guest_safe_area();
        let bar_bottom = self.metrics.guest_pt.height - self.metrics.safe_insets.bottom;
        let bar_top = bar_bottom - TAB_BAR_HEIGHT_PT;
        if point.x < safe.origin.x
            || point.x >= safe.max_x()
            || point.y < bar_top
            || point.y >= bar_bottom
            || safe.size.width <= 0.0
        {
            return None;
        }
        let index = ((point.x - safe.origin.x) / safe.size.width * self.tab_count as f64) as usize;
        Some(index.min(self.tab_count - 1))
    }

    fn ensure_main(&self, thread: ThreadId) -> Result<(), SessionError> {
        if thread == self.main_thread {
            Ok(())
        } else {
            Err(SessionError::WrongThread)
        }
    }

    fn lock_queue(&self) -> MutexGuard<'_, VecDeque<InputEvent>> {
        // A panic while holding the queue must not make the session unusable;
        // no input is processed while this lock is held.
        self.queue.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn drain_queue(&mut self, preserve_timing: bool) -> Result<usize, SessionError> {
        if !matches!(self.lifecycle, Lifecycle::SceneReady | Lifecycle::Active) {
            return Ok(0);
        }
        let mut drained = 0;
        loop {
            let event = self.lock_queue().pop_front();
            let Some(event) = event else {
                break;
            };
            if preserve_timing {
                self.host.wait_until(event.timestamp_ns);
            }
            self.process_on_guest_main(event);
            drained += 1;
        }
        Ok(drained)
    }

    fn process_on_guest_main(&mut self, event: InputEvent) {
        let position = self.metrics.host_to_guest(event.position);

        if event.cancelled {
            if self
                .pending
                .active_pointers
                .remove(&event.pointer_id)
                .is_none()
            {
                return;
            }
        } else {
            match event.phase {
                InputPhase::Begin => {
                    if self.pending.is_active(event.pointer_id) {
                        return;
                    }
                    let state = PointerState {
                        pointer_id: event.pointer_id,
                        phase: event.phase,
                        timestamp_ns: event.timestamp_ns,
                        position,
                        pressure: event.pressure,
                        down_tab: self.tab_at_guest_point(position),
                    };
                    self.pending.active_pointers.insert(event.pointer_id, state);
                }
                InputPhase::Move => {
                    let Some(pointer) = self.pending.active_pointers.get_mut(&event.pointer_id)
                    else {
                        return;
                    };
                    pointer.phase = event.phase;
                    pointer.timestamp_ns = event.timestamp_ns;
                    pointer.position = position;
                    pointer.pressure = event.pressure;
                }
                InputPhase::End => {
                    let Some(pointer) = self.pending.active_pointers.remove(&event.pointer_id)
                    else {
                        return;
                    };
                    let up_tab = self.tab_at_guest_point(position);
                    if pointer.down_tab.is_some() && pointer.down_tab == up_tab {
                        self.selected_tab = up_tab;
                    }
                }
            }
        }

        self.delivered.push(DeliveredInput {
            pointer_id: event.pointer_id,
            phase: event.phase,
            timestamp_ns: event.timestamp_ns,
            host_position: event.position,
            position,
            pressure: event.pressure,
            cancelled: event.cancelled,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeHost {
        now_ns: u64,
        logs: Vec<String>,
        waits: Vec<u64>,
        frames: Vec<(u32, u32, usize, u64)>,
    }

    impl HostApi for FakeHost {
        fn now_ns(&mut self) -> u64 {
            self.now_ns
        }

        fn log(&mut self, message: &str) {
            self.logs.push(message.to_owned());
        }

        fn present_frame(&mut self, frame: Frame<'_>) {
            self.frames.push((
                frame.width,
                frame.height,
                frame.stride_bytes,
                frame.timestamp_ns,
            ));
        }

        fn wait_until(&mut self, deadline_ns: u64) {
            self.waits.push(deadline_ns);
            self.now_ns = self.now_ns.max(deadline_ns);
        }
    }

    fn target() -> TargetIdentity {
        TargetIdentity::new("com.example.HarmoniosTabs", [0x5a; 32], [0xa5; 16], "18.0")
    }

    fn phone_metrics() -> DisplayMetrics {
        DisplayMetrics {
            physical_px: Size::new(1170.0, 2532.0),
            host_vp: Size::new(390.0, 844.0),
            guest_pt: Size::new(390.0, 844.0),
            orientation: Orientation::Portrait,
            safe_insets: Insets {
                top: 47.0,
                left: 0.0,
                bottom: 34.0,
                right: 0.0,
            },
        }
    }

    fn session(metrics: DisplayMetrics) -> GuestSession<FakeHost> {
        GuestSession::new(target(), metrics, ThreadId(7), 3, FakeHost::default())
    }

    fn tap(pointer_id: u64, start_ns: u64, position: Point) -> [InputEvent; 2] {
        [
            InputEvent::new(pointer_id, InputPhase::Begin, start_ns, position),
            InputEvent {
                pressure: 0.0,
                ..InputEvent::new(pointer_id, InputPhase::End, start_ns + 100, position)
            },
        ]
    }

    #[test]
    fn queue_preserves_fifo_order_on_guest_main() {
        let mut session = session(phone_metrics());
        session.mark_scene_ready(ThreadId(7)).unwrap();
        let position = Point::new(300.0, 762.857);
        session
            .queue_input(InputEvent::new(9, InputPhase::Begin, 30, position))
            .unwrap();
        session
            .queue_input(InputEvent::new(9, InputPhase::Move, 20, position))
            .unwrap();
        session
            .queue_input(InputEvent::new(9, InputPhase::End, 10, position))
            .unwrap();

        assert_eq!(session.pump_guest_main(ThreadId(7)), Ok(3));
        let phases: Vec<_> = session
            .delivered()
            .iter()
            .map(|event| event.phase)
            .collect();
        let timestamps: Vec<_> = session
            .delivered()
            .iter()
            .map(|event| event.timestamp_ns)
            .collect();
        assert_eq!(
            phases,
            [InputPhase::Begin, InputPhase::Move, InputPhase::End]
        );
        assert_eq!(timestamps, [30, 20, 10]);
        assert!(session.queued_events().is_empty());
    }

    #[test]
    fn scene_readiness_and_main_thread_gate_delivery() {
        let mut session = session(phone_metrics());
        for event in tap(1, 1_000, Point::new(300.0, 762.857)) {
            session.queue_input(event).unwrap();
        }

        assert_eq!(session.pump_guest_main(ThreadId(7)), Ok(0));
        assert_eq!(session.pending_event_count(), 2);
        assert!(session.delivered().is_empty());

        session.mark_scene_ready(ThreadId(7)).unwrap();
        assert_eq!(
            session.pump_guest_main(ThreadId(99)),
            Err(SessionError::WrongThread)
        );
        assert_eq!(session.pending_event_count(), 2);
        assert_eq!(session.pump_guest_main(ThreadId(7)), Ok(2));
        assert_eq!(session.selected_tab, Some(2));
    }

    #[test]
    fn begin_and_end_in_the_same_tab_update_selection_state() {
        let mut session = session(phone_metrics());
        session.mark_scene_ready(ThreadId(7)).unwrap();
        assert_eq!(session.selected_tab, None);

        for event in tap(42, 500, Point::new(300.0, 762.857)) {
            session.queue_input(event).unwrap();
        }
        session.pump_guest_main(ThreadId(7)).unwrap();

        assert_eq!(session.selected_tab, Some(2));
        assert!(!session.pending.is_active(42));
        assert_eq!(
            session.tab_at_guest_point(Point::new(300.0, 762.857)),
            Some(2)
        );
        assert_eq!(session.tab_at_guest_point(Point::new(300.0, 820.0)), None);
    }

    #[test]
    fn cancel_releases_pointer_without_selecting_a_tab() {
        let mut session = session(phone_metrics());
        session.mark_scene_ready(ThreadId(7)).unwrap();
        let position = Point::new(300.0, 762.857);
        session
            .queue_input(InputEvent::new(3, InputPhase::Begin, 10, position))
            .unwrap();
        session.pump_guest_main(ThreadId(7)).unwrap();
        assert!(session.pending.is_active(3));

        session
            .queue_input(InputEvent::cancel(3, 20, position))
            .unwrap();
        session
            .queue_input(InputEvent::new(3, InputPhase::End, 30, position))
            .unwrap();
        session.pump_guest_main(ThreadId(7)).unwrap();

        assert!(!session.pending.is_active(3));
        assert_eq!(session.selected_tab, None);
        assert_eq!(session.delivered().len(), 2);
        assert!(session.delivered()[1].cancelled);
    }

    #[test]
    fn simultaneous_pointers_keep_independent_identity_and_capture() {
        let mut session = session(phone_metrics());
        session.mark_scene_ready(ThreadId(7)).unwrap();
        let first = Point::new(50.0, 780.0);
        let second = Point::new(300.0, 780.0);
        session
            .queue_input(InputEvent::new(11, InputPhase::Begin, 10, first))
            .unwrap();
        session
            .queue_input(InputEvent::new(22, InputPhase::Begin, 11, second))
            .unwrap();
        session.pump_guest_main(ThreadId(7)).unwrap();
        assert!(session.pending.is_active(11));
        assert!(session.pending.is_active(22));
        assert_eq!(session.pending.pointer(11).unwrap().down_tab, Some(0));
        assert_eq!(session.pending.pointer(22).unwrap().down_tab, Some(2));

        session
            .queue_input(InputEvent::new(
                22,
                InputPhase::Move,
                12,
                Point::new(310.0, 780.0),
            ))
            .unwrap();
        session
            .queue_input(InputEvent::new(11, InputPhase::End, 13, first))
            .unwrap();
        session.pump_guest_main(ThreadId(7)).unwrap();
        assert!(!session.pending.is_active(11));
        assert!(session.pending.is_active(22));
        assert_eq!(session.pending.pointer(22).unwrap().position.x, 310.0);
        assert_eq!(session.selected_tab, Some(0));

        session
            .queue_input(InputEvent::cancel(22, 14, second))
            .unwrap();
        session.pump_guest_main(ThreadId(7)).unwrap();
        assert!(!session.pending.is_active(22));
        assert_eq!(session.selected_tab, Some(0));
        let ids: Vec<_> = session
            .delivered()
            .iter()
            .map(|event| event.pointer_id)
            .collect();
        assert_eq!(ids, [11, 22, 22, 11, 22]);
    }

    #[test]
    fn coordinate_transforms_are_inverses_for_every_orientation() {
        for orientation in [
            Orientation::Portrait,
            Orientation::PortraitUpsideDown,
            Orientation::LandscapeLeft,
            Orientation::LandscapeRight,
        ] {
            let landscape = matches!(
                orientation,
                Orientation::LandscapeLeft | Orientation::LandscapeRight
            );
            let metrics = DisplayMetrics {
                orientation,
                guest_pt: if landscape {
                    Size::new(844.0, 390.0)
                } else {
                    Size::new(390.0, 844.0)
                },
                ..phone_metrics()
            };
            for point in [
                Point::new(0.0, 0.0),
                Point::new(17.25, 91.75),
                Point::new(300.0, 762.857),
                Point::new(390.0, 844.0),
            ] {
                let round_trip = metrics.guest_to_host(metrics.host_to_guest(point));
                assert!((round_trip.x - point.x).abs() <= 1e-6, "{orientation:?}");
                assert!((round_trip.y - point.y).abs() <= 1e-6, "{orientation:?}");
            }
        }

        let upside_down = DisplayMetrics {
            orientation: Orientation::PortraitUpsideDown,
            ..phone_metrics()
        };
        assert_eq!(
            upside_down.host_to_guest(Point::new(0.0, 0.0)),
            Point::new(390.0, 844.0)
        );
    }

    #[test]
    fn display_scale_is_derived_and_safe_area_is_in_guest_points() {
        let metrics = DisplayMetrics {
            physical_px: Size::new(800.0, 1600.0),
            host_vp: Size::new(200.0, 400.0),
            guest_pt: Size::new(100.0, 200.0),
            orientation: Orientation::Portrait,
            safe_insets: Insets {
                top: 10.0,
                left: 2.0,
                bottom: 20.0,
                right: 4.0,
            },
        };
        assert_eq!(
            metrics.host_to_guest(Point::new(50.0, 100.0)),
            Point::new(25.0, 50.0)
        );
        let safe = metrics.guest_safe_area();
        assert_eq!(safe.origin, Point::new(2.0, 10.0));
        assert_eq!(safe.size, Size::new(94.0, 170.0));
        assert_eq!(
            metrics.guest_to_host(Point::new(25.0, 50.0)),
            Point::new(50.0, 100.0)
        );
    }

    #[test]
    fn replay_actual_tap_trace_selects_tab_two() {
        let metrics = phone_metrics();
        let mut session = session(metrics);
        session.mark_scene_ready(ThreadId(7)).unwrap();
        let position = Point::new(300.0, 762.857);
        let trace = InputTrace {
            target: target(),
            metrics,
            events: tap(77, 1_000_000, position).to_vec(),
        };

        assert_eq!(session.replay(&trace, ThreadId(7)), Ok(2));
        assert_eq!(session.selected_tab, Some(2));
        assert_eq!(session.delivered().len(), 2);
        assert_eq!(session.delivered()[0].phase, InputPhase::Begin);
        assert_eq!(session.delivered()[1].phase, InputPhase::End);
        for event in session.delivered() {
            assert!((event.position.x - 300.0).abs() <= 1e-6);
            assert!((event.position.y - 762.857).abs() <= 1e-6);
            assert_eq!(event.pointer_id, 77);
        }
        assert!(!session.pending.is_active(77));
        assert_eq!(session.host().waits, [1_000_000, 1_000_100]);
        assert_eq!(session.host().now_ns, 1_000_100);
    }
}
