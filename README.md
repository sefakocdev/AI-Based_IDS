# AI-Based Intrusion Detection System (IDS)

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![Framework](https://img.shields.io/badge/framework-PyQt5-green.svg)
![ML](https://img.shields.io/badge/ML-XGBoost-orange.svg)

## 🌟 Introduction

This project presents an **AI-Based Intrusion Detection System (IDS)** designed specifically for mobile networks. The system utilizes machine learning techniques to detect and classify network traffic as either benign or malicious. A key feature of the proposed system is its support for both **real-time detection** from live network interfaces and **historical flow detection** from recorded flows.

## ✨ Key Features

- 🔍 **Real-time Network Monitoring**: Live detection from network interfaces
- 📊 **Historical Flow Analysis**: Analysis of recorded network flows
- 🤖 **Machine Learning-based Detection**: XGBoost classifier for intelligent threat detection
- 🖥️ **Interactive GUI**: Python-based graphical interface using PyQt5
- 📈 **Visualization**: Dynamic charts and tables for detection results
- 🔄 **Model Retraining**: Capability to retrain the model with new data
- 🎯 **Multi-class Classification**: Detection of various attack types including:
  - DoS/DDoS attacks
  - Port scanning
  - Infiltration attacks
  - Web attacks
  - Brute force attacks (FTP-Patator, SSH-Patator)
  - Botnet activities

### Prerequisites

- Python 3.7 or higher
- Windows OS (for live packet capture)
- Administrative privileges (for network interface access)

### Installations

1. **Install Python dependencies**
   ```bash
   pip install pandas numpy joblib scikit-learn xgboost matplotlib seaborn scapy pyqt5
   ```

2. **Install Npcap for packet capture** (Windows only)
   - Download and install from: https://npcap.com/
   - Required for live network traffic monitoring

## 🔧 Usage

### Real-time Network Monitoring

1. Launch the application
2. Select "Real-time Detection" mode
3. Choose your network interface from the dropdown
4. Click "Start Monitoring"
5. View live detection results in the table

### Historical Flow Analysis

1. Select "Historical Analysis" mode
2. Run analysis on the historical data
3. Add and send flows from Historical Flow Simulation Window
4. View classification results and statistics

### Model Retraining

1. Navigate to the training section
2. Ensure your datasets are in the `dataset/` folder
3. Click "Train Model" to retrain with updated data
4. New models will be saved in the `models/` folder

## 📊 Supported Attack Types

The system can detect and classify the following types of network attacks:

- **DoS Attacks**: DoS Hulk, DoS GoldenEye, DoS Slowhttptest, DoS slowloris
- **DDoS Attacks**: Distributed Denial of Service
- **Brute Force**: FTP-Patator, SSH-Patator
- **Network Reconnaissance**: Port Scanning
- **Advanced Threats**: Infiltration, Heartbleed, Bot activities
- **Web Attacks**: Various web-based attack patterns
- **Benign Traffic**: Normal network traffic classification

## 🧠 Machine Learning Model

The system uses **XGBoost (Extreme Gradient Boosting)** as the core machine learning algorithm:

- **Algorithm**: XGBoost Classifier
- **Feature Engineering**: 19 key network flow features
- **Preprocessing**: StandardScaler for feature normalization
- **Encoding**: LabelEncoder for multi-class classification
- **Performance**: High accuracy with efficient real-time prediction

### Key Features Used

- Protocol type
- Flow duration and packet statistics
- Forward/backward packet lengths
- Flow bytes and packets per second
- TCP flag counts (SYN, ACK, PSH, RST)
- Header lengths and packet characteristics

## 📈 Visualization Features

The system provides comprehensive visualization capabilities:

- **Real-time Detection Charts**: Live monitoring graphs
- **Confusion Matrix**: Model performance evaluation
- **Feature Importance**: Most significant detection features
- **Class Distribution**: Attack type frequency analysis
- **Classification Metrics**: Precision, recall, and F1-score

