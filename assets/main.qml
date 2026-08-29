import bb.cascades 1.4
import bb.cascades.pickers 1.0

Page {
    id: appPage
    property string currentSection: share.outgoingReady ? "send" : "activity"
    property bool outgoingSignal: share.outgoingReady

    onOutgoingSignalChanged: {
        if (outgoingSignal)
            currentSection = "send"
    }

    actionBarAutoHideBehavior: ActionBarAutoHideBehavior.Disabled
    actionBarVisibility: ChromeVisibility.Visible

    actions: [
        ActionItem {
            title: qsTr("Attivit\u00e0")
            imageSource: "asset:///images/nav_activity.png"
            ActionBar.placement: ActionBarPlacement.OnBar
            onTriggered: appPage.currentSection = "activity"
        },
        ActionItem {
            title: qsTr("Ricevi")
            imageSource: "asset:///images/nav_receive.png"
            ActionBar.placement: ActionBarPlacement.Signature
            onTriggered: appPage.currentSection = "receive"
        },
        ActionItem {
            title: qsTr("Invia")
            imageSource: "asset:///images/nav_send.png"
            ActionBar.placement: ActionBarPlacement.OnBar
            onTriggered: {
                appPage.currentSection = "send"
                if (!share.scanning && share.devicesEmpty)
                    share.scanDevices()
            }
        }
    ]

    Container {
        background: Color.create("#ff12161b")
        layout: DockLayout {}

        Container {
            visible: appPage.currentSection == "activity"
            horizontalAlignment: HorizontalAlignment.Fill
            verticalAlignment: VerticalAlignment.Fill
            layout: StackLayout { orientation: LayoutOrientation.TopToBottom }

            Header { title: qsTr("Attivit\u00e0") }

            Container {
                visible: share.transferActive
                horizontalAlignment: HorizontalAlignment.Fill
                leftPadding: 24.0
                rightPadding: 24.0
                topPadding: 14.0
                bottomPadding: 14.0
                background: Color.create("#ff1d252d")
                Container {
                    layout: StackLayout { orientation: LayoutOrientation.LeftToRight }
                    Label {
                        text: share.sendActive ? qsTr("Invio in corso") : qsTr("Ricezione in corso")
                        textStyle.fontWeight: FontWeight.Bold
                        layoutProperties: StackLayoutProperties { spaceQuota: 1.0 }
                    }
                    Label {
                        text: share.transferProgressText
                        textStyle.base: SystemDefaults.TextStyles.SmallText
                        textStyle.color: Color.LightGray
                    }
                }
                ProgressIndicator {
                    fromValue: 0.0
                    toValue: 1.0
                    value: share.transferProgress
                    horizontalAlignment: HorizontalAlignment.Fill
                }
            }

            Container {
                horizontalAlignment: HorizontalAlignment.Fill
                leftPadding: 24.0
                rightPadding: 12.0
                topPadding: 10.0
                bottomPadding: 8.0
                layout: StackLayout { orientation: LayoutOrientation.LeftToRight }
                Label {
                    text: share.eventCount == 1 ? qsTr("1 elemento") : qsTr("%1 elementi").arg(share.eventCount)
                    verticalAlignment: VerticalAlignment.Center
                    textStyle.base: SystemDefaults.TextStyles.SmallText
                    textStyle.color: Color.LightGray
                    layoutProperties: StackLayoutProperties { spaceQuota: 1.0 }
                }
                Button {
                    text: qsTr("Pulisci")
                    enabled: share.eventCount > 0
                    onClicked: share.clearHistory()
                }
            }

            Container {
                layoutProperties: StackLayoutProperties { spaceQuota: 1.0 }
                horizontalAlignment: HorizontalAlignment.Fill
                verticalAlignment: VerticalAlignment.Fill
                layout: DockLayout {}
                Container {
                    visible: share.eventsEmpty
                    horizontalAlignment: HorizontalAlignment.Center
                    verticalAlignment: VerticalAlignment.Center
                    leftPadding: 40.0
                    rightPadding: 40.0
                    Label {
                        text: qsTr("Nessun trasferimento")
                        horizontalAlignment: HorizontalAlignment.Center
                        textStyle.base: SystemDefaults.TextStyles.SubtitleText
                        textStyle.fontWeight: FontWeight.Bold
                    }
                    Label {
                        text: qsTr("I file inviati e ricevuti compariranno qui.")
                        multiline: true
                        horizontalAlignment: HorizontalAlignment.Center
                        textStyle.base: SystemDefaults.TextStyles.SmallText
                        textStyle.textAlign: TextAlign.Center
                        textStyle.color: Color.LightGray
                    }
                }

                ListView {
                    visible: !share.eventsEmpty
                    horizontalAlignment: HorizontalAlignment.Fill
                    verticalAlignment: VerticalAlignment.Fill
                    dataModel: share.events
                    onTriggered: {
                        var item = dataModel.data(indexPath)
                        if (item.path)
                            share.openReceivedFile(item.path)
                    }
                    listItemComponents: [
                        ListItemComponent {
                            type: ""
                            CustomListItem {
                                Container {
                                    leftPadding: 24.0
                                    rightPadding: 24.0
                                    topPadding: 15.0
                                    bottomPadding: 15.0
                                    horizontalAlignment: HorizontalAlignment.Fill
                                    layout: StackLayout { orientation: LayoutOrientation.LeftToRight }
                                    Container {
                                        layoutProperties: StackLayoutProperties { spaceQuota: 1.0 }
                                        Label {
                                            text: ListItemData.title
                                            textStyle.fontWeight: FontWeight.Bold
                                        }
                                        Label {
                                            text: ListItemData.detail
                                            multiline: true
                                            textStyle.base: SystemDefaults.TextStyles.SmallText
                                            textStyle.color: Color.LightGray
                                        }
                                    }
                                    Label {
                                        visible: ListItemData.path != undefined
                                        text: ">"
                                        verticalAlignment: VerticalAlignment.Center
                                        textStyle.base: SystemDefaults.TextStyles.SubtitleText
                                        textStyle.color: Color.create("#ff48a7e8")
                                    }
                                }
                            }
                        }
                    ]
                }
            }
        }

        ScrollView {
            visible: appPage.currentSection == "receive"
            horizontalAlignment: HorizontalAlignment.Fill
            verticalAlignment: VerticalAlignment.Fill
            Container {
                horizontalAlignment: HorizontalAlignment.Fill
                bottomPadding: 36.0
                Header { title: qsTr("Ricevi") }
                Container {
                    leftPadding: 24.0
                    rightPadding: 24.0
                    topPadding: 20.0
                    Container {
                        horizontalAlignment: HorizontalAlignment.Fill
                        leftPadding: 20.0
                        rightPadding: 20.0
                        topPadding: 18.0
                        bottomPadding: 18.0
                        background: Color.create("#ff1d252d")
                        layout: StackLayout { orientation: LayoutOrientation.LeftToRight }
                        Container {
                            layoutProperties: StackLayoutProperties { spaceQuota: 1.0 }
                            Label {
                                text: share.transferPending ? qsTr("Richiesta in arrivo") :
                                      (share.transferActive ? qsTr("Ricezione in corso") : qsTr("Pronto a ricevere"))
                                textStyle.fontWeight: FontWeight.Bold
                            }
                            Label {
                                text: qsTr("Visibile sulla Wi-Fi come BBX Share")
                                textStyle.base: SystemDefaults.TextStyles.SmallText
                                textStyle.color: Color.LightGray
                            }
                        }
                        ActivityIndicator {
                            running: !share.transferPending
                            verticalAlignment: VerticalAlignment.Center
                        }
                    }

                    Header { title: qsTr("Da Android") }
                    Container {
                        topPadding: 10.0; bottomPadding: 10.0
                        layout: StackLayout { orientation: LayoutOrientation.LeftToRight }
                        Label { text: "1"; minWidth: 52.0; textStyle.fontWeight: FontWeight.Bold; textStyle.color: Color.create("#ff48a7e8") }
                        Label { text: qsTr("Collega i due telefoni alla stessa rete Wi-Fi."); multiline: true; layoutProperties: StackLayoutProperties { spaceQuota: 1.0 } }
                    }
                    Container {
                        topPadding: 10.0; bottomPadding: 10.0
                        layout: StackLayout { orientation: LayoutOrientation.LeftToRight }
                        Label { text: "2"; minWidth: 52.0; textStyle.fontWeight: FontWeight.Bold; textStyle.color: Color.create("#ff48a7e8") }
                        Label { text: qsTr("Da Quick Share su Android scegli BBX Share."); multiline: true; layoutProperties: StackLayoutProperties { spaceQuota: 1.0 } }
                    }
                    Container {
                        topPadding: 10.0; bottomPadding: 10.0
                        layout: StackLayout { orientation: LayoutOrientation.LeftToRight }
                        Label { text: "3"; minWidth: 52.0; textStyle.fontWeight: FontWeight.Bold; textStyle.color: Color.create("#ff48a7e8") }
                        Label { text: qsTr("Confronta il PIN e accetta sul BlackBerry."); multiline: true; layoutProperties: StackLayoutProperties { spaceQuota: 1.0 } }
                    }

                    Header { title: qsTr("Destinazione") }
                    Label {
                        text: "File Manager  /  downloads  /  BBXShare"
                        multiline: true
                        textStyle.base: SystemDefaults.TextStyles.SmallText
                        textStyle.color: Color.LightGray
                    }
                    Label {
                        text: qsTr("Tocca un file ricevuto in Attivit\u00e0 per aprire la sua cartella nel File Manager.")
                        multiline: true
                        textStyle.base: SystemDefaults.TextStyles.SmallText
                        textStyle.color: Color.LightGray
                    }
                }
            }
        }

        ScrollView {
            visible: appPage.currentSection == "send"
            horizontalAlignment: HorizontalAlignment.Fill
            verticalAlignment: VerticalAlignment.Fill
            Container {
                horizontalAlignment: HorizontalAlignment.Fill
                bottomPadding: 36.0
                Header { title: qsTr("Invia") }
                Container {
                    leftPadding: 24.0
                    rightPadding: 24.0
                    topPadding: 20.0
                    Label {
                        text: qsTr("Scegli un file")
                        textStyle.base: SystemDefaults.TextStyles.SubtitleText
                        textStyle.fontWeight: FontWeight.Bold
                    }
                    Button {
                        visible: !share.outgoingReady
                        text: qsTr("Apri File Picker")
                        horizontalAlignment: HorizontalAlignment.Fill
                        onClicked: outgoingPicker.open()
                    }
                    Button {
                        visible: share.outgoingReady
                        text: qsTr("Scegli un altro file")
                        horizontalAlignment: HorizontalAlignment.Fill
                        onClicked: outgoingPicker.open()
                    }

                    Container {
                        visible: share.outgoingReady
                        topMargin: 18.0
                        horizontalAlignment: HorizontalAlignment.Fill
                        leftPadding: 20.0
                        rightPadding: 20.0
                        topPadding: 18.0
                        bottomPadding: 18.0
                        background: Color.create("#ff1d252d")
                        Label { text: share.outgoingName; multiline: true; textStyle.fontWeight: FontWeight.Bold }
                        Label { text: share.outgoingDetail; textStyle.base: SystemDefaults.TextStyles.SmallText; textStyle.color: Color.LightGray }
                        Button {
                            text: qsTr("Rimuovi")
                            enabled: !share.sendActive
                            horizontalAlignment: HorizontalAlignment.Fill
                            onClicked: share.clearOutgoingFile()
                        }
                    }

                    Container {
                        visible: share.sendActive || share.sendStatus.length > 0
                        topMargin: 16.0
                        horizontalAlignment: HorizontalAlignment.Fill
                        leftPadding: 20.0
                        rightPadding: 20.0
                        topPadding: 16.0
                        bottomPadding: 16.0
                        background: share.sendFailed ?
                                    Color.create("#ff47252a") : Color.create("#ff173047")
                        Container {
                            layout: StackLayout { orientation: LayoutOrientation.LeftToRight }
                            Label {
                                text: share.sendActive ? qsTr("Trasferimento in corso") :
                                      (share.sendFailed ? qsTr("Invio non riuscito") : qsTr("Stato invio"))
                                textStyle.fontWeight: FontWeight.Bold
                                layoutProperties: StackLayoutProperties { spaceQuota: 1.0 }
                            }
                            ActivityIndicator {
                                running: share.sendActive
                                visible: share.sendActive
                            }
                        }
                        Label {
                            text: share.sendStatus
                            multiline: true
                            textStyle.base: SystemDefaults.TextStyles.SmallText
                            textStyle.color: Color.LightGray
                        }
                        ProgressIndicator {
                            visible: share.sendActive
                            fromValue: 0.0
                            toValue: 1.0
                            value: share.transferProgress
                            horizontalAlignment: HorizontalAlignment.Fill
                        }
                        Label {
                            visible: share.sendActive && share.transferProgressText.length > 0
                            text: share.transferProgressText
                            textStyle.base: SystemDefaults.TextStyles.SmallText
                            textStyle.color: Color.LightGray
                        }
                    }

                    Header { title: qsTr("Dispositivi vicini"); visible: share.outgoingReady }
                    Label {
                        visible: share.outgoingReady
                        text: qsTr("Cerca i receiver Quick Share disponibili sulla stessa Wi-Fi.")
                        multiline: true
                        textStyle.base: SystemDefaults.TextStyles.SmallText
                        textStyle.color: Color.LightGray
                    }
                    Button {
                        visible: share.outgoingReady
                        text: share.scanning ? qsTr("Ricerca in corso…") : qsTr("Cerca dispositivi")
                        enabled: !share.scanning && !share.sendActive
                        horizontalAlignment: HorizontalAlignment.Fill
                        onClicked: share.scanDevices()
                    }
                    ActivityIndicator {
                        visible: share.scanning
                        running: share.scanning
                        horizontalAlignment: HorizontalAlignment.Center
                    }
                    Label {
                        visible: share.outgoingReady && !share.scanning && share.devicesEmpty
                        text: qsTr("Nessun device trovato. Attiva Quick Share sul telefono e riprova.")
                        multiline: true
                        textStyle.base: SystemDefaults.TextStyles.SmallText
                        textStyle.color: Color.LightGray
                    }
                    Container {
                        visible: share.outgoingReady && !share.devicesEmpty
                        horizontalAlignment: HorizontalAlignment.Fill
                        preferredHeight: 240.0
                        clipContentToBounds: true
                        ListView {
                            horizontalAlignment: HorizontalAlignment.Fill
                            verticalAlignment: VerticalAlignment.Fill
                            dataModel: share.devices
                        onTriggered: {
                            var device = dataModel.data(indexPath)
                            share.selectDevice(device.address, device.port,
                                               device.name, device.instance)
                        }
                        listItemComponents: [
                            ListItemComponent {
                                type: ""
                                CustomListItem {
                                    Container {
                                        leftPadding: 18.0
                                        rightPadding: 18.0
                                        topPadding: 12.0
                                        bottomPadding: 12.0
                                        horizontalAlignment: HorizontalAlignment.Fill
                                        layout: StackLayout { orientation: LayoutOrientation.LeftToRight }
                                        Container {
                                            layoutProperties: StackLayoutProperties { spaceQuota: 1.0 }
                                            Label { text: ListItemData.name; textStyle.fontWeight: FontWeight.Bold }
                                            Label {
                                                text: qsTr("Quick Share · %1").arg(ListItemData.address)
                                                textStyle.base: SystemDefaults.TextStyles.SmallText
                                                textStyle.color: Color.LightGray
                                            }
                                        }
                                        Label {
                                            text: ">"
                                            verticalAlignment: VerticalAlignment.Center
                                            textStyle.base: SystemDefaults.TextStyles.SubtitleText
                                            textStyle.color: Color.create("#ff48a7e8")
                                        }
                                    }
                                }
                            }
                        ]
                        }
                    }
                    Container {
                        visible: share.deviceReady
                        topMargin: 12.0
                        horizontalAlignment: HorizontalAlignment.Fill
                        leftPadding: 20.0
                        rightPadding: 20.0
                        topPadding: 16.0
                        bottomPadding: 16.0
                        background: Color.create("#ff173047")
                        Label {
                            text: qsTr("Destinatario: %1").arg(share.selectedDeviceName)
                            multiline: true
                            textStyle.fontWeight: FontWeight.Bold
                            textStyle.color: Color.create("#ff75c5ff")
                        }
                        Label {
                            text: qsTr("Pronto sulla rete Wi-Fi")
                            textStyle.base: SystemDefaults.TextStyles.SmallText
                            textStyle.color: Color.LightGray
                        }
                        Button {
                            text: share.sendActive ? qsTr("Invio in corso…") :
                                  (share.outgoingReady ? qsTr("Invia %1").arg(share.outgoingName) : qsTr("Scegli prima un file"))
                            enabled: share.outgoingReady && !share.transferActive && !share.sendActive
                            horizontalAlignment: HorizontalAlignment.Fill
                            onClicked: share.sendOutgoing()
                        }
                        Button {
                            text: qsTr("Cambia dispositivo")
                            enabled: !share.sendActive
                            horizontalAlignment: HorizontalAlignment.Fill
                            onClicked: {
                                share.clearDeviceSelection()
                                share.scanDevices()
                            }
                        }
                    }
                }
            }
        }

        Container {
            visible: share.transferPending
            horizontalAlignment: HorizontalAlignment.Fill
            verticalAlignment: VerticalAlignment.Bottom
            leftPadding: 24.0
            rightPadding: 24.0
            topPadding: 22.0
            bottomPadding: 22.0
            background: Color.create("#ff27343f")
            Label { text: qsTr("RICHIESTA QUICK SHARE"); textStyle.base: SystemDefaults.TextStyles.SmallText; textStyle.color: Color.create("#ff65b5ff") }
            Label { text: share.pendingTitle; multiline: true; textStyle.base: SystemDefaults.TextStyles.SubtitleText; textStyle.fontWeight: FontWeight.Bold }
            Label { text: share.pendingDetail; multiline: true; textStyle.base: SystemDefaults.TextStyles.SmallText; textStyle.color: Color.LightGray }
            Container {
                topPadding: 14.0
                layout: StackLayout { orientation: LayoutOrientation.LeftToRight }
                Button {
                    text: qsTr("Rifiuta")
                    layoutProperties: StackLayoutProperties { spaceQuota: 1.0 }
                    onClicked: share.rejectTransfer()
                }
                Button {
                    text: qsTr("Accetta")
                    layoutProperties: StackLayoutProperties { spaceQuota: 1.0 }
                    onClicked: share.acceptTransfer()
                }
            }
        }
    }

    attachedObjects: [
        FilePicker {
            id: outgoingPicker
            title: qsTr("Scegli uno o più file da inviare")
            mode: FilePickerMode.PickerMultiple
            viewMode: FilePickerViewMode.ListView
            filter: ["*"]
            directories: ["/accounts/1000/shared"]
            onFileSelected: {
                if (selectedFiles.length > 0) {
                    share.selectOutgoingFiles(selectedFiles)
                    appPage.currentSection = "send"
                    if (!share.scanning && share.devicesEmpty)
                        share.scanDevices()
                }
            }
        }
    ]

    onCreationCompleted: {
        if (share.outgoingReady)
            appPage.currentSection = "send"
    }

}
