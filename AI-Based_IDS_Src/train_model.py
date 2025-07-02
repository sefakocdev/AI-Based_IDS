import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.utils import shuffle
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns
import shutil
import csv

def train_model_xgb():
    # 0. Copy CSV files to updated dataset folder
    datasetFolder = 'dataset'
    updatedDataSetFolder = 'updatedDataset'
    # Remove updated folder if it exists to start fresh
    if os.path.exists(updatedDataSetFolder):
        shutil.rmtree(updatedDataSetFolder)
    os.makedirs(updatedDataSetFolder)
    # Copy all CSV files from dataset folder to updated dataset folder
    for filename in os.listdir(datasetFolder):
        if filename.endswith('.csv'):
            src_path = os.path.join(datasetFolder, filename)
            dst_path = os.path.join(updatedDataSetFolder, filename)
            shutil.copy2(src_path, dst_path)

    # 1. Load and merge all CSV files into a single dataframe
    def load_and_merge_csvs(dataset_path=updatedDataSetFolder):
        dataframes = []
        for file in os.listdir(dataset_path):
            if file.endswith(".csv"):
                df = pd.read_csv(os.path.join(dataset_path, file), low_memory=False, encoding='latin1')
                dataframes.append(df)
        df = pd.concat(dataframes, ignore_index=True)
        df.columns = df.columns.str.strip()
        return df

    df = load_and_merge_csvs()

    # 2. Data cleaning - remove infinite values and NaN entries
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # 3. Class filtering - keep only common attack types for better model performance
    allowed_labels = [
        'FTP-Patator', 'Infiltration', 'DoS Hulk', 'DoS GoldenEye', 'SSH-Patator', 'Heartbleed',
        'PortScan', 'Bot', 'DoS Slowhttptest', 'BENIGN', 'DoS slowloris', 'DDoS'
    ]
    df = df[df['Label'].isin(allowed_labels)]

    # 4. Select only features that can be extracted in real-time packet analysis
    selected_columns = [
        'Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
        'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
        'Flow Bytes/s', 'Flow Packets/s',
        'SYN Flag Count', 'ACK Flag Count', 'PSH Flag Count', 'RST Flag Count',
        'Fwd Header Length', 'Bwd Header Length', 'Packet Length Mean'
    ]
    df = df[selected_columns + ['Label']]

    # 5. Label encoding for multi-class classification
    le = LabelEncoder()
    df['LabelEncoded'] = le.fit_transform(df['Label'])

    # 6. Shuffle the dataset to ensure random distribution
    df = shuffle(df, random_state=42)

    # 7. Reserve 20% of data for testing purposes
    test_data = pd.DataFrame(columns=df.columns)
    for label in df['Label'].unique():
        label_data = df[df['Label'] == label]
        test_size = int(len(label_data) * 0.2)
        test_data_label = label_data.sample(n=test_size, random_state=42)
        test_data = pd.concat([test_data, test_data_label])

    # 8. Save test data to testDataset/testData.csv (excluding LabelEncoded column)
    os.makedirs("testDataset", exist_ok=True)
    test_data_path = os.path.join("testDataset", "testData.csv")
    if os.path.exists(test_data_path):
        os.remove(test_data_path)
    test_data[selected_columns + ['Label']].to_csv(test_data_path, index=False)

    # 9. Remove test data from the original dataset to prevent data leakage
    df = df.drop(test_data.index)

    # 10. Remove test data from CSV files to maintain data integrity
    def remove_test_data_from_csvs(test_data, dataset_path=updatedDataSetFolder):
        test_data_columns = set(test_data.columns)
        for file in os.listdir(dataset_path):
            if file.endswith('.csv'):
                file_path = os.path.join(dataset_path, file)
                df_csv = pd.read_csv(file_path, encoding='latin1')
                # Find common columns between datasets
                common_columns = list(set(df_csv.columns) & test_data_columns)
                # Skip file if insufficient common columns for proper merging
                if len(common_columns) < 2:
                    print(f"Skipping {file} due to insufficient common columns.")
                    continue
                # Merge operation based on common columns only
                df_csv = df_csv.merge(
                    test_data[common_columns].drop_duplicates(),
                    on=common_columns,
                    how='left',
                    indicator=True
                ).query('_merge == "left_only"').drop(columns=['_merge'])
                df_csv.to_csv(file_path, index=False)
    remove_test_data_from_csvs(test_data)

    # 11. Separate features (X) and target labels (y)
    X = df[selected_columns]
    y = df['LabelEncoded']

    # 12. Feature scaling for better model performance
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 13. Split data into training and testing sets with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.3, random_state=42, stratify=y
    )

    # 14. Configure and train XGBoost model for multi-class classification
    model = xgb.XGBClassifier(
        objective='multi:softmax',
        num_class=len(le.classes_),
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.1,
        reg_lambda=1.0,
        eval_metric='mlogloss',
        random_state=42
    )
    model.fit(X_train, y_train)

    # 15. Save trained model and preprocessing components
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/ids_model_xgb_multiclass.pkl')
    joblib.dump(scaler, 'models/scaler.pkl')
    joblib.dump(le, 'models/label_encoder.pkl')

    # 16. Generate classification report and display results both in terminal and as charts
    y_pred = model.predict(X_test)
    print("\nMulti-class validation results with XGBoost:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # Convert classification report to dataframe for visualization
    report_dict = classification_report(y_test, y_pred, target_names=le.classes_, output_dict=True)
    report_df = pd.DataFrame(report_dict).transpose()

    # Create Precision, Recall, F1-score bar chart for performance visualization
    plt.figure(figsize=(12, 8))
    metrics = ['precision', 'recall', 'f1-score']
    report_df_plot = report_df.loc[le.classes_, metrics]
    report_df_plot.plot(kind='bar')
    plt.title("Classification Report Metrics by Class")
    plt.xlabel("Classes")
    plt.ylabel("Score")
    plt.ylim(0, 1.05)
    plt.legend(loc='lower right')
    plt.tight_layout()
    plt.savefig('charts/classification_report_metrics.png', dpi=300)
    plt.close()

    # Create support bar chart showing sample count per class
    plt.figure(figsize=(12, 6))
    bars = plt.bar(le.classes_, report_df.loc[le.classes_, 'support'], color='skyblue')
    plt.title("Support (Sample Count) per Class")
    plt.xlabel("Classes")
    plt.ylabel("Number of Samples")
    # Barların üstüne değer yaz
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 5, int(yval), ha='center', va='bottom', fontweight='bold')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('charts/class_support.png', dpi=300)
    plt.close()

    # 17. Create and save label distribution visualization
    plt.figure(figsize=(12, 6))
    label_counts = df['Label'].value_counts()
    bars = sns.barplot(x=label_counts.index, y=label_counts.values, palette='viridis')
    # Barların üstüne değer yaz
    for bar in bars.patches:
        height = bar.get_height()
        bars.annotate(f'{int(height)}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 5),  # offset
                    textcoords='offset points',
                    ha='center', va='bottom', fontweight='bold')
    plt.xticks(rotation=45, ha='right')
    plt.title("Dataset Label Distribution")
    plt.ylabel("Count")
    plt.xlabel("Labels")
    plt.tight_layout()
    plt.savefig('charts/label_distribution.png', dpi=300)
    plt.close()

    print("\nKullanılan etiketlerin dağılımı:")
    print(label_counts)

    # 18. Generate feature importance chart to understand model decision factors
    os.makedirs('charts', exist_ok=True)
    plt.figure(figsize=(10, 8))  # Increased width and height
    xgb.plot_importance(model, max_num_features=20, height=0.5, ax=plt.gca())
    plt.title("Feature Importance Chart")
    plt.tight_layout()
    plt.savefig('charts/feature_importance.png', dpi=300)
    plt.close()

    # 19. Generate confusion matrix for detailed classification performance analysis
    plt.figure(figsize=(12, 10))  # Increased size
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", 
                xticklabels=le.classes_, yticklabels=le.classes_)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix")
    plt.tight_layout()
    plt.savefig('charts/confusion_matrix.png', dpi=300)
    plt.close()

    # 20. Test the model with testData.csv and generate performance visualization
    test_data = pd.read_csv("testDataset/testData.csv")
    X_test_data = test_data[selected_columns]
    y_test_data = le.transform(test_data['Label'])

    X_test_data_scaled = scaler.transform(X_test_data)
    y_test_data_pred = model.predict(X_test_data_scaled)

    # 21. Create new CSV file for simulation purposes with proper headers
    file_name = "testDataset/historical.csv"
    if os.path.exists(file_name):
        os.remove(file_name)
    headers = [
        "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
        "Flow Bytes/s", "Flow Packets/s", "SYN Flag Count", "ACK Flag Count",
        "PSH Flag Count", "RST Flag Count", "Fwd Header Length", "Bwd Header Length",
        "Packet Length Mean"
    ]
    with open(file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)

    # 22. Create combined Accuracy vs Support Chart (line + bar chart)
    os.makedirs('charts', exist_ok=True)
    plt.figure(figsize=(12, 6))
    support_values = report_df.loc[le.classes_, 'support']
    accuracy_values = report_df.loc[le.classes_, 'f1-score']
    ax = sns.barplot(x=le.classes_, y=support_values, color='skyblue', label='Support')
    ax2 = ax.twinx()
    sns.lineplot(x=le.classes_, y=accuracy_values, marker='o', color='red', label='Accuracy (F1-score)', ax=ax2)
    ax.set_xlabel('Classes')
    ax.set_ylabel('Support (Sample Count)', color='blue')
    ax2.set_ylabel('Accuracy (F1-score)', color='red')
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha='right')
    plt.title('Class Support vs Accuracy (F1-score)')
    ax.legend(loc='upper left')
    ax2.legend(loc='upper right')
    plt.tight_layout()
    plt.savefig('charts/overall_accuracy_vs_support.png', dpi=300)
    plt.close()

