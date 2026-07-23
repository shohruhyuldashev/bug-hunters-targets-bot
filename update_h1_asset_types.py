import sqlite3
import os

def main():
    db_path = os.getenv("DATABASE_PATH", "data/db.sqlite3")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    mapping = {
        "URL": "URL",
        "WILDCARD": "Wildcard",
        "CIDR": "CIDR",
        "IP_ADDRESS": "IP Address",
        "SOURCE_CODE": "Source Code",
        "DOWNLOADABLE_EXECUTABLES": "Executable",
        "HARDWARE": "Hardware/IoT",
        "GOOGLE_PLAY_APP_ID": "Android: Play Store",
        "APPLE_STORE_APP_ID": "Apple: App Store",
        "WINDOWS_APP_STORE_APP_ID": "Windows: App Store",
        "OTHER": "Other",
        "SMART_CONTRACT": "Smart Contract",
        "API": "API",
    }
    
    for raw, mapped in mapping.items():
        if raw != mapped:
            cursor.execute("UPDATE relay_targets SET asset_type = ? WHERE asset_type = ?", (mapped, raw))
            cursor.execute("UPDATE relay_targets SET asset_type = ? WHERE asset_type = ?", (mapped, raw.lower()))
            
    conn.commit()
    conn.close()
    print("Database asset types updated successfully.")

if __name__ == "__main__":
    main()
