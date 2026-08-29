import bb.cascades 1.4

Page {
    Container {
        leftPadding: 24.0
        rightPadding: 24.0
        topPadding: 24.0
        bottomPadding: 24.0
        background: Color.Black
        Label {
            text: "Errore UI BBX Share"
            textStyle.base: SystemDefaults.TextStyles.TitleText
            textStyle.fontWeight: FontWeight.Bold
        }
        Label {
            text: qmlError.text
            multiline: true
            textStyle.base: SystemDefaults.TextStyles.SmallText
            textStyle.color: Color.White
        }
    }
}
