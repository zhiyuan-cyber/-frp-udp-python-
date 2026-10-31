/**
 * Widgets.ets —— 复用的小组件
 *
 * 用 @Builder 全局函数而不是自定义组件，是为了让调用方
 * 能直接组合、少一层状态传递（这些纯展示组件没有自己的状态）。
 */

/** 圆角卡片 */
@Builder
export function Card(content: () => void) {
  Column() {
    content()
  }
  .width('100%')
  .padding(16)
  .backgroundColor('#1A2028')
  .borderRadius(14)
  .border({ width: 1, color: '#2A333F' })
}

/** 区块标题 */
@Builder
export function SectionTitle(title: string, extra: string) {
  Row() {
    Text(title)
      .fontSize(16)
      .fontWeight(FontWeight.Bold)
      .fontColor('#E8EDF4')
    Blank()
    if (extra.length > 0) {
      Text(extra)
        .fontSize(12)
        .fontColor('#6B7785')
    }
  }
  .width('100%')
  .margin({ bottom: 10 })
}

/** 指标小格（数值 + 标签） */
@Builder
export function StatTile(label: string, value: string, hint: string, valueColor: string) {
  Column() {
    Text(value)
      .fontSize(19)
      .fontWeight(FontWeight.Bold)
      .fontColor(valueColor)
      .maxLines(1)
      .textOverflow({ overflow: TextOverflow.Ellipsis })
    Text(label)
      .fontSize(11)
      .fontColor('#9AA7B8')
      .margin({ top: 4 })
    if (hint.length > 0) {
      Text(hint)
        .fontSize(10)
        .fontColor('#6B7785')
        .margin({ top: 2 })
    }
  }
  .alignItems(HorizontalAlign.Start)
  .layoutWeight(1)
  .padding({ top: 10, bottom: 10, left: 12, right: 8 })
}

/** 一行"键 - 值" */
@Builder
export function KeyValue(key: string, value: string, valueColor: string) {
  Row() {
    Text(key)
      .fontSize(13)
      .fontColor('#9AA7B8')
    Blank()
    Text(value)
      .fontSize(13)
      .fontColor(valueColor)
      .maxLines(2)
      .textOverflow({ overflow: TextOverflow.Ellipsis })
      .textAlign(TextAlign.End)
      .layoutWeight(1)
  }
  .width('100%')
  .padding({ top: 7, bottom: 7 })
}

/** 细分隔线 */
@Builder
export function Divider() {
  Divider()
    .color('#2A333F')
    .strokeWidth(1)
    .margin({ top: 4, bottom: 4 })
}

/** 空态提示 */
@Builder
export function EmptyHint(text: string) {
  Column() {
    Text(text)
      .fontSize(13)
      .fontColor('#6B7785')
      .textAlign(TextAlign.Center)
  }
  .width('100%')
  .padding(28)
  .alignItems(HorizontalAlign.Center)
}
