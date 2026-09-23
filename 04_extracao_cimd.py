import kagglehub

# Download latest version
path = kagglehub.dataset_download("datasetengineer/cybertec-iiot-malware-dataset-cimd-2024")

print("Path to dataset files:", path)