# 果易通图标

中文显示名称：果易通。内部项目名、Ability 名称和 bundleName 保持原有标识。

图标以果实轮廓、叶片与连通环表达跨平台应用互通，采用青蓝到薄荷绿的立体渐变，
搭配深蓝底色。使用内置 image_gen 工具生成透明图形，再按鸿蒙分层图标的
安全区域进行等比缩放和透明留白处理。

- `guoyitong-icon.png`：1024 × 1024 合成预览。
- `../../AppScope/resources/base/media/foreground.png`：1024 × 1024 透明前景。
- `../../AppScope/resources/base/media/background.png`：1024 × 1024 深蓝渐变背景。
- 入口模块同步保存前景、背景，并以 `startIcon.png` 提供 256 × 256 启动图标。
- `layered_image.json` 继续关联前景和背景；浅色、深色启动窗口统一使用深蓝底色。

生成提示词（内置工具，透明背景）：

```text
Use case: logo-brand
Asset type: production HarmonyOS adaptive launcher icon foreground for a Chinese app called 果易通, which runs iOS apps on HarmonyOS.
Primary request: create one beautiful, polished, distinctive abstract fruit-and-connection symbol. A single rounded flowing loop forms the body of an abstract fruit, with a small detached tilted leaf above; a subtle opening or interlocking ribbon sweep suggests effortless connection between platforms. Original geometry, not the Apple logo, no bite, no recognizable existing brand.
Style: premium minimal sculptural app mark, smooth clean silhouette, subtle satin depth and luminous cyan-to-mint gradient. Restrained, confident, highly readable at 48 pixels. No lettering.
Composition: square 1024x1024 transparent canvas. Center the whole symbol including leaf within the central 62 percent of canvas width and height, generous transparent margins for HarmonyOS adaptive masking. Large simple shapes, balanced weight, crisp edges.
Colors: bright cyan, turquoise and mint highlights, designed to sit over a deep midnight navy background.
Constraints: transparent background, symbol only, no rounded-square tile, no background, no mockup, no borders, no text, no watermark, no extra objects, no drop shadow outside the symbol.
```
