from train_model import train_model_xgb
from GUI.main_ui import Ui_MainWindow as MainUI
from GUI.simulation_ui import Ui_MainWindow as SimulationUI
from GUI.charts_ui import Ui_MainWindow as ChartsUI

import sys
import os
import pandas as pd
import random
import numpy as np
import joblib
import pickle
from scapy.all import get_if_list, sniff, AsyncSniffer, TCP, IP
from scapy.arch.windows import get_windows_if_list
from PyQt5.QtWidgets import QApplication, QMainWindow, QHeaderView, QTableWidgetItem, QMessageBox
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QColor, QPixmap
import PyQt5.QtCore as QtCore
from scapy.layers.inet import TCP, IP
from scapy.layers.inet6 import IPv6
import time

realtimeColumns = [
    'Prediction', 'Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Bwd Packets', 
    'Fwd Packet Len Max', 'Fwd Packet Len Min', 'Fwd Packet Len Mean',
    'Bwd Packet Len Max', 'Bwd Packet Len Min', 'Bwd Packet Len Mean',
    'Flow Bytes/s', 'Flow Packets/s',
    'SYN Flag Count', 'ACK Flag Count', 'PSH Flag Count', 'RST Flag Count',
    'Fwd Header Len', 'Bwd Header Len', 'Packet Len Mean'
]

hisFlowColumns = [
    'Label','Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Bwd Packets', 
    'Fwd Packet Len Max', 'Fwd Packet Len Min', 'Fwd Packet Len Mean',
    'Bwd Packet Len Max', 'Bwd Packet Len Min', 'Bwd Packet Len Mean',
    'Flow Bytes/s', 'Flow Packets/s',
    'SYN Flag Count', 'ACK Flag Count', 'PSH Flag Count', 'RST Flag Count',
    'Fwd Header Len', 'Bwd Header Len', 'Packet Len Mean'
]

hisCsvColumns = [
    'Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Flow Bytes/s', 'Flow Packets/s', 'SYN Flag Count', 'ACK Flag Count',
    'PSH Flag Count', 'RST Flag Count', 'Fwd Header Length',
    'Bwd Header Length', 'Packet Length Mean'
]

class ChartsWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = ChartsUI()
        self.ui.setupUi(self)
        self.initCharts()
        self.ui.buttonShow.clicked.connect(self.buttonShowSlot)

    def initCharts(self):
        self.ui.comboBoxType.addItem("Label Distrubution")
        self.ui.comboBoxType.addItem("Feature Importance")
        self.ui.comboBoxType.addItem("Test Samples Distrubution")
        self.ui.comboBoxType.addItem("Confusion Matrix")
        self.ui.comboBoxType.addItem("Classification Report")
        self.ui.comboBoxType.addItem("Overall Accuracy vs Support")
        self.ui.comboBoxType.setStyleSheet("padding: 1px 18px 1px 3px; min-width: 6em; text-align: center; border: 2px solid white; color: rgb(255, 255, 255); font: 75 14pt 'MS Shell Dlg 2'; font-weight: bold; padding: 2px 12px;")

    def buttonShowSlot(self):
        selected = self.ui.comboBoxType.currentText()
        pixmap = None

        if selected == "Label Distrubution":
            pixmap = QPixmap("charts/label_distribution.png")
        elif selected == "Feature Importance":
            pixmap = QPixmap("charts/feature_importance.png")
        elif selected == "Test Samples Distrubution":
            pixmap = QPixmap("charts/class_support.png")
        elif selected == "Confusion Matrix":
            pixmap = QPixmap("charts/confusion_matrix.png")
        elif selected == "Classification Report":
            pixmap = QPixmap("charts/classification_report_metrics.png")
        elif selected == "Overall Accuracy vs Support":
            pixmap = QPixmap("charts/overall_accuracy_vs_support.png")
        else:
            self.ui.labelChart.clear()
            return

        if pixmap is None or pixmap.isNull():
            QMessageBox.critical(self, "Error", f"Image could not be loaded: {selected}")
            return

        self.ui.labelChart.setPixmap(pixmap)
        self.ui.labelChart.setScaledContents(True)



class SimulationWindow(QMainWindow):
    signalSendAllCompleted = pyqtSignal()  # Signal definition for completed send operation

    def __init__(self):
        super().__init__()
        self.ui = SimulationUI()
        self.ui.setupUi(self)
        self.init()
        self.ui.buttonAdd.clicked.connect(self.buttonAddSlot)
        self.ui.buttonSendAll.clicked.connect(self.buttonSendAllSlot)
        self.ui.buttonShuffle.clicked.connect(self.buttonShuffleSlot)
        self.ui.buttonClearAll.clicked.connect(self.buttonClearAllSlot)

    def init(self):
        self.buttonClearAllSlot()
        self.setSpinboxMaximums()

    def resetSpinboxes(self):
        self.ui.spinBox_benign.setValue(0)
        self.ui.spinBox_doshulk.setValue(0)
        self.ui.spinBox_portscan.setValue(0)
        self.ui.spinBox_ddos.setValue(0)
        self.ui.spinBox_dosgoldeneye.setValue(0)
        self.ui.spinBox_ftp.setValue(0)
        self.ui.spinBox_ssh.setValue(0)
        self.ui.spinBox_dosslowloris.setValue(0)
        self.ui.spinBox_dosslowhttp.setValue(0)
        self.ui.spinBox_bot.setValue(0)
        self.ui.spinBox_infiltration.setValue(0)
        self.ui.spinBox_heartbleed.setValue(0)

    def setSpinboxMaximums(self):
        df = pd.read_csv("testDataset/testData.csv")
        # Get label counts from the test dataset
        label_counts = df['Label'].value_counts()
        label_to_spinbox = {
            'BENIGN': self.ui.spinBox_benign,
            'DoS Hulk': self.ui.spinBox_doshulk,
            'PortScan': self.ui.spinBox_portscan,
            'DDoS': self.ui.spinBox_ddos,
            'DoS GoldenEye': self.ui.spinBox_dosgoldeneye,
            'FTP-Patator': self.ui.spinBox_ftp,
            'SSH-Patator': self.ui.spinBox_ssh,
            'DoS slowloris': self.ui.spinBox_dosslowloris,
            'DoS Slowhttptest': self.ui.spinBox_dosslowhttp,
            'Bot': self.ui.spinBox_bot,
            'Infiltration': self.ui.spinBox_infiltration,
            'Heartbleed': self.ui.spinBox_heartbleed,
        }
        # Set maximum value for each label's spinbox based on available data
        for label, spinbox in label_to_spinbox.items():
            count = label_counts.get(label, 0)  # Use 0 if label doesn't exist
            spinbox.setMaximum(count)
        
    def buttonClearAllSlot(self):
        self.resetSpinboxes()
        self.ui.tableWidgetHisFlow.clear()
        self.ui.tableWidgetHisFlow.setRowCount(0)
        self.ui.tableWidgetHisFlow.setColumnCount(len(hisFlowColumns))
        self.ui.tableWidgetHisFlow.setHorizontalHeaderLabels(hisFlowColumns)
        self.ui.tableWidgetHisFlow.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        
    def buttonAddSlot(self):
        df = pd.read_csv("testDataset/testData.csv")

        label_to_spinbox = {
            'BENIGN': self.ui.spinBox_benign,
            'DoS Hulk': self.ui.spinBox_doshulk,
            'PortScan': self.ui.spinBox_portscan,
            'DDoS': self.ui.spinBox_ddos,
            'DoS GoldenEye': self.ui.spinBox_dosgoldeneye,
            'FTP-Patator': self.ui.spinBox_ftp,
            'SSH-Patator': self.ui.spinBox_ssh,
            'DoS slowloris': self.ui.spinBox_dosslowloris,
            'DoS Slowhttptest': self.ui.spinBox_dosslowhttp,
            'Bot': self.ui.spinBox_bot,
            'Infiltration': self.ui.spinBox_infiltration,
            'Heartbleed': self.ui.spinBox_heartbleed,
        }

        col_mapping = {
            'Label': 'Label',
            'Protocol': 'Protocol',
            'Flow Duration': 'Flow Duration',
            'Total Fwd Packets': 'Total Fwd Packets',
            'Total Bwd Packets': 'Total Backward Packets',
            'Fwd Packet Len Max': 'Fwd Packet Length Max',
            'Fwd Packet Len Min': 'Fwd Packet Length Min',
            'Fwd Packet Len Mean': 'Fwd Packet Length Mean',
            'Bwd Packet Len Max': 'Bwd Packet Length Max',
            'Bwd Packet Len Min': 'Bwd Packet Length Min',
            'Bwd Packet Len Mean': 'Bwd Packet Length Mean',
            'Flow Bytes/s': 'Flow Bytes/s',
            'Flow Packets/s': 'Flow Packets/s',
            'SYN Flag Count': 'SYN Flag Count',
            'ACK Flag Count': 'ACK Flag Count',
            'PSH Flag Count': 'PSH Flag Count',
            'RST Flag Count': 'RST Flag Count',
            'Fwd Header Len': 'Fwd Header Length',
            'Bwd Header Len': 'Bwd Header Length',
            'Packet Len Mean': 'Packet Length Mean'
        }

        # Get current row count for table insertion
        current_row = self.ui.tableWidgetHisFlow.rowCount()

        for label, spinbox in label_to_spinbox.items():
            count = spinbox.value()
            if count == 0:
                continue

            rows = df[df['Label'] == label].head(count)

            for _, row_data in rows.iterrows():
                self.ui.tableWidgetHisFlow.insertRow(current_row)
                for col_index, col_name in enumerate(hisFlowColumns):
                    if col_name == "Prediction":
                        value = "N/A"
                    else:
                        csv_col = col_mapping.get(col_name, col_name)
                        value = str(row_data[csv_col]) if csv_col in row_data else ""
                    self.ui.tableWidgetHisFlow.setItem(current_row, col_index, QTableWidgetItem(value))
                self.ui.tableWidgetHisFlow.setVerticalHeaderItem(current_row, QTableWidgetItem(str(current_row + 1)))
                current_row += 1
    
    def buttonSendAllSlot(self):
        rows = self.ui.tableWidgetHisFlow.rowCount()
        cols = self.ui.tableWidgetHisFlow.columnCount()
        data_to_append = []
        for row in range(rows):
            row_dict = {}
            for col_index in range(cols):
                header = self.ui.tableWidgetHisFlow.horizontalHeaderItem(col_index).text()
                if header == "Label" or header == "Prediction":
                    continue
                item = self.ui.tableWidgetHisFlow.item(row, col_index)
                value = item.text() if item else None
                # Map header from hisFlowColumns to hisCsvColumns format
                header_mapping = {
                    'Total Bwd Packets': 'Total Backward Packets',
                    'Fwd Packet Len Max': 'Fwd Packet Length Max',
                    'Fwd Packet Len Min': 'Fwd Packet Length Min',
                    'Fwd Packet Len Mean': 'Fwd Packet Length Mean',
                    'Bwd Packet Len Max': 'Bwd Packet Length Max',
                    'Bwd Packet Len Min': 'Bwd Packet Length Min',
                    'Bwd Packet Len Mean': 'Bwd Packet Length Mean',
                    'Fwd Header Len': 'Fwd Header Length',
                    'Bwd Header Len': 'Bwd Header Length',
                    'Packet Len Mean': 'Packet Length Mean',
                    # Other columns remain the same
                }
                mapped_header = header_mapping.get(header, header)
                row_dict[mapped_header] = value
            data_to_append.append(row_dict)
        if data_to_append:
            df_new = pd.DataFrame(data_to_append)
            df_new = df_new[hisCsvColumns]  # Only required columns in correct order
            # Append to CSV file
            historical_path = "testDataset/historical.csv"
            try:
                if os.path.exists(historical_path):
                    df_existing = pd.read_csv(historical_path)
                    df_combined = pd.concat([df_existing, df_new], ignore_index=True)
                    df_combined.to_csv(historical_path, index=False)
                else:
                    df_new.to_csv(historical_path, index=False)
            except Exception as e:
                print("CSV append error:", e)
        self.signalSendAllCompleted.emit()

    def buttonShuffleSlot(self):
        row_count = self.ui.tableWidgetHisFlow.rowCount()
        col_count = self.ui.tableWidgetHisFlow.columnCount()
        rows_data = []
        for row in range(row_count):
            row_items = []
            for col in range(col_count):
                item = self.ui.tableWidgetHisFlow.item(row, col)
                # If cell is empty, use empty string
                row_items.append(item.text() if item else "")
            rows_data.append(row_items)
        random.shuffle(rows_data)
        for row in range(row_count):
            for col in range(col_count):
                self.ui.tableWidgetHisFlow.setItem(row, col, QTableWidgetItem(rows_data[row][col]))
            # Reset row number display
            self.ui.tableWidgetHisFlow.setVerticalHeaderItem(row, QTableWidgetItem(str(row + 1)))            


class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = MainUI()
        self.ui.setupUi(self)
        self.initNetworks()
        self.model = joblib.load("models/ids_model_xgb_multiclass.pkl")
        self.scaler = joblib.load("models/scaler.pkl")
        self.label_encoder = joblib.load("models/label_encoder.pkl")
        self.simulation_window = None
        self.charts_window = None
        self.realTimeListening = 0
        self.blink_state = False
        self.blink_timer = QTimer()
        self.blink_timer.timeout.connect(self.listenFlowSlot)
        self.label_counts = {
            "BENIGN": 0,
            "DoS Hulk": 0,
            "PortScan": 0,
            "DDoS": 0,
            "DoS GoldenEye": 0,
            "FTP-Patator": 0,
            "SSH-Patator": 0,
            "DoS slowloris": 0,
            "DoS Slowhttptest": 0,
            "Bot": 0,
            "Infiltration": 0,
            "Heartbleed": 0
        }
        self.buttonClearAllSlot()
        self.ui.buttonRetrain.clicked.connect(self.buttonRetrainClicked)
        self.ui.buttonChartsWin.clicked.connect(self.openChartsWinSlot)
        self.ui.buttonSimWin.clicked.connect(self.openSimulationWindowSlot)
        self.ui.buttonStartStop.clicked.connect(self.buttonStartStopSlot)
        self.ui.buttonClearAll.clicked.connect(self.buttonClearAllSlot)


    def initNetworks(self):
        interfaces = get_windows_if_list()
        filtered_ifaces = []
        # Keywords to filter out unwanted network interfaces
        exclude_keywords = [
            'WFP', 'Npcap', 'Kernel Debugger', 'Pseudo-Interface',
            'Teredo', 'IP-HTTPS', '6to4', 'VirtualBox', 'Bluetooth', 'QoS Packet Scheduler',
            'VMware', "çekirdek", "Çekirdek", "Hata", "Driver", "Driver-0000"
        ]
        for iface in interfaces:
            name = iface['name']
            # Keep Local Area Connection* interfaces specifically
            if name.startswith("Local Area Connection*") or name.startswith("Yerel Ağ Bağlantısı*"):
                continue
            if any(kw in name for kw in exclude_keywords):
                continue

            filtered_ifaces.append(iface)

        # Add filtered interfaces to the combobox
        for i, iface in enumerate(filtered_ifaces):
            self.ui.comboBoxNetwork.addItem(iface['name'])


    # Enable/disable all UI elements during processing
    def setUIEnabled(self, enabled):
            self.setEnabled(enabled)

    def buttonRetrainClicked(self):
        # Disable UI during retraining process
        self.setUIEnabled(False)
        # Create "Model is retraining..." message box
        self.msg_box = QMessageBox(self)
        self.msg_box.setWindowTitle("Please Wait")
        self.msg_box.setText("Model is retraining...")
        self.msg_box.setStandardButtons(QMessageBox.NoButton)
        self.msg_box.show()
        # Queue the operation with QTimer: first show message box, then train model
        QTimer.singleShot(100, self.runRetrainProcess)

    def runRetrainProcess(self):
        # Train the model using XGBoost
        train_model_xgb()
        # Close the message box
        self.msg_box.accept()
        # Re-enable the UI
        self.setUIEnabled(True)

    def openChartsWinSlot(self):
            if self.charts_window is None:
                self.charts_window = ChartsWindow()
            self.charts_window.show()

    def openSimulationWindowSlot(self):
        if self.simulation_window is None:
            self.simulation_window = SimulationWindow()
            self.simulation_window.signalSendAllCompleted.connect(self.onSendAllCompleted)
        self.simulation_window.show()

    from scapy.all import AsyncSniffer

    def buttonStartStopSlot(self):
        if self.realTimeListening == 0:
            if not self.ui.checkBoxHisFlow.isChecked():
                selected_iface = self.ui.comboBoxNetwork.currentText()
                if selected_iface == "  Select Network Interface":
                    return

                # Start AsyncSniffer for real-time packet capture
                self.sniffer = AsyncSniffer(
                    iface=selected_iface,
                    prn=self.process_packet,
                    store=False
                )
                try:
                    self.sniffer.start()
                    self.realTimeListening = 1
                except Exception as e:
                    print(f"[Sniffer] Başlatma hatası: {e}")
                    self.sniffer = None
                    return

            else:
                # Historical prediction
                self.predict_and_load_historical()
                self.realTimeListening = 1

            self.ui.comboBoxNetwork.setDisabled(True)
            self.ui.checkBoxHisFlow.setDisabled(True)
            self.blink_timer.start(1000)
            self.ui.buttonStartStop.setText("Stop")

        else:
            # Stop the sniffer
            if hasattr(self, 'sniffer') and self.sniffer:
                try:
                    self.sniffer.stop()
                except Exception as e:
                    print(f"[Sniffer] Durdurma hatası: {e}")
                self.sniffer = None

            self.realTimeListening = 0
            self.ui.comboBoxNetwork.setDisabled(False)
            self.ui.checkBoxHisFlow.setDisabled(False)
            self.blink_timer.stop()
            self.ui.textBrowserStatus.setStyleSheet(
                "border: 2px solid #8f8f91; border-radius: 15px;background-color: rgb(255, 0, 0);"
            )
            self.ui.buttonStartStop.setText("Start")


    def listenFlowSlot(self):
        if self.blink_state:
            self.ui.textBrowserStatus.setStyleSheet("border: 2px solid #8f8f91; border-radius: 15px;background-color: rgb(40, 40, 40);")
        else:
            self.ui.textBrowserStatus.setStyleSheet("border: 2px solid #8f8f91; border-radius: 15px;background-color: rgb(0, 255, 0);")
        self.blink_state = not self.blink_state
        
    def buttonClearAllSlot(self):
        self.resetLabels()
        self.ui.tableWidgetRealtime.clear()
        self.ui.tableWidgetRealtime.setRowCount(0)
        self.ui.tableWidgetRealtime.setColumnCount(len(realtimeColumns))
        self.ui.tableWidgetRealtime.setHorizontalHeaderLabels(realtimeColumns)
        self.ui.tableWidgetRealtime.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        
    def resetLabels(self):
        for label in self.label_counts:
            self.label_counts[label] = 0
        self.update_label_counters_ui()
        
    def update_label_counters_ui(self):
        self.ui.label_benign.setText(str(self.label_counts["BENIGN"]))
        self.ui.label_doshulk.setText(str(self.label_counts["DoS Hulk"]))
        self.ui.label_portscan.setText(str(self.label_counts["PortScan"]))
        self.ui.label_ddos.setText(str(self.label_counts["DDoS"]))
        self.ui.label_dosgoldeneye.setText(str(self.label_counts["DoS GoldenEye"]))
        self.ui.label_ftp.setText(str(self.label_counts["FTP-Patator"]))
        self.ui.label_ssh.setText(str(self.label_counts["SSH-Patator"]))
        self.ui.label_dosslowloris.setText(str(self.label_counts["DoS slowloris"]))
        self.ui.label_dosslowhttp.setText(str(self.label_counts["DoS Slowhttptest"]))
        self.ui.label_bot.setText(str(self.label_counts["Bot"]))
        self.ui.label_infiltration.setText(str(self.label_counts["Infiltration"]))
        self.ui.label_heartbleed.setText(str(self.label_counts["Heartbleed"]))

    def predict_and_load_historical(self):
        df = pd.read_csv("testDataset/historical.csv")
        # If file contains only column headers (i.e., is empty), exit function
        if df.empty:
            return

        # Prepare features and make predictions
        X = df.drop("Label", axis=1, errors="ignore")
        X_scaled = self.scaler.transform(X)
        y_pred = self.model.predict(X_scaled)
        y_pred_labels = self.label_encoder.inverse_transform(y_pred)

        # Label counter UI elements mapping
        label_counters = {
            "BENIGN": self.ui.label_benign,
            "DoS Hulk": self.ui.label_doshulk,
            "PortScan": self.ui.label_portscan,
            "DDoS": self.ui.label_ddos,
            "DoS GoldenEye": self.ui.label_dosgoldeneye,
            "FTP-Patator": self.ui.label_ftp,
            "SSH-Patator": self.ui.label_ssh,
            "DoS slowloris": self.ui.label_dosslowloris,
            "DoS Slowhttptest": self.ui.label_dosslowhttp,
            "Bot": self.ui.label_bot,
            "Infiltration": self.ui.label_infiltration,
            "Heartbleed": self.ui.label_heartbleed
        }

        for i, row in df.iterrows():
            label = y_pred_labels[i]

            # Add row to the realtime table
            row_position = self.ui.tableWidgetRealtime.rowCount()
            self.ui.tableWidgetRealtime.insertRow(row_position)

            # Write features to table columns
            for j, value in enumerate(row):
                self.ui.tableWidgetRealtime.setItem(row_position, j+1, QTableWidgetItem(str(value)))

            # Add predicted label to first column
            self.ui.tableWidgetRealtime.setItem(row_position, 0, QTableWidgetItem(label))

            # Update counter for this label
            if label in self.label_counts:
                self.label_counts[label] += 1
                self.update_label_counters_ui()
                
        # Clear CSV file (keep only column headers)
        df.iloc[0:0].to_csv("testDataset/historical.csv", index=False)


    def onSendAllCompleted(self):
        if self.ui.checkBoxHisFlow.isChecked() and  self.realTimeListening == 1:
            self.predict_and_load_historical()

    def process_packet(self, packet):
        features = self.extract_features(packet)
        if features is None or len(features) != 19:
            print("Feature extraction failed.")
            return

        # Feature scaling for prediction
        # scaled = self.scaler.transform([features])
        # Create DataFrame with column names for proper scaling
        feature_df = pd.DataFrame([features], columns=hisCsvColumns)
        scaled = self.scaler.transform(feature_df)
        # Make prediction using the trained model
        prediction = self.model.predict(scaled)[0]
        label = self.label_encoder.inverse_transform([prediction])[0]
        
        # Send to UI for display
        self.handle_new_flow(features, label)
        time.sleep(1)

    def extract_features(self, packet):
        try:
            proto = packet[IP].proto if IP in packet else packet[IPv6].nh if IPv6 in packet else 0
            pkt_len = len(packet)
            # Some features cannot be extracted currently, placeholder values are used
            return [
                proto,              # Protocol
                0,                  # Flow Duration (placeholder)
                1, 0,               # Fwd/Bwd packets
                pkt_len, pkt_len, pkt_len,   # Fwd lengths
                0, 0, 0,            # Bwd lengths
                0, 0,               # Bytes/s, Packets/s
                int(TCP in packet and packet[TCP].flags & 0x02 != 0),  # SYN
                int(TCP in packet and packet[TCP].flags & 0x10 != 0),  # ACK
                int(TCP in packet and packet[TCP].flags & 0x08 != 0),  # PSH
                int(TCP in packet and packet[TCP].flags & 0x04 != 0),  # RST
                len(packet[IP]) if IP in packet else 0,  # Fwd header len
                0,                  # Bwd header len
                pkt_len             # Mean
            ]
        except Exception as e:
            print(f"[extract_features] Error: {e}")
            return None

    
    def handle_new_flow(self, features, label):
        row_position = self.ui.tableWidgetRealtime.rowCount()
        self.ui.tableWidgetRealtime.insertRow(row_position)
        # Add prediction to first column
        self.ui.tableWidgetRealtime.setItem(row_position, 0, QTableWidgetItem(label))
        for i, val in enumerate(features):
            self.ui.tableWidgetRealtime.setItem(row_position, i+1, QTableWidgetItem(str(val)))
        # Update counter for this label
        if label in self.label_counts:
            self.label_counts[label] += 1
            self.update_label_counters_ui()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())

