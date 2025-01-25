import os
import hashlib
import json

class FileHashMonitor:
    def __init__(self, directory, hash_file="hashes.json"):
        """
        Initializes the FileHashMonitor.

        :param directory: Directory to monitor for file changes.
        :param hash_file: Path to the file where hash values will be stored.
        """
        self.directory = directory
        self.hash_file = hash_file
        self.file_hashes = self.load_hashes()

    def calculate_hash(self, file_path):
        """
        Calculate the hash of a file.

        :param file_path: Path to the file.
        :return: Hash value of the file as a hexadecimal string.
        """
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            return None

    def load_hashes(self):
        """
        Load previously stored hash values from the hash file.

        :return: Dictionary of file paths and their hash values.
        """
        if os.path.exists(self.hash_file):
            with open(self.hash_file, "r") as f:
                return json.load(f)
        return {}

    def save_hashes(self):
        """
        Save the current hash values to the hash file.
        """
        with open(self.hash_file, "w") as f:
            json.dump(self.file_hashes, f, indent=4)

    def monitor(self):
        """
        Monitor the directory for file changes and report any modifications.
        """
        changes_detected = False

        for root, _, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                new_hash = self.calculate_hash(file_path)

                if file_path not in self.file_hashes:
                    print(f"New file detected: {file_path}")
                    changes_detected = True
                elif self.file_hashes[file_path] != new_hash:
                    print(f"File modified: {file_path}")
                    changes_detected = True

                self.file_hashes[file_path] = new_hash

        deleted_files = [
            file_path for file_path in self.file_hashes if not os.path.exists(file_path)
        ]
        for file_path in deleted_files:
            print(f"File deleted: {file_path}")
            del self.file_hashes[file_path]
            changes_detected = True

        if changes_detected:
            self.save_hashes()
        else:
            print("No changes detected.")

if __name__ == "__main__":
    directory_to_monitor = input("Enter the directory to monitor: ").strip()
    monitor = FileHashMonitor(directory_to_monitor)

    while True:
        command = input("Enter 'check' to scan for changes or 'exit' to quit: ").strip().lower()
        if command == "check":
            monitor.monitor()
        elif command == "exit":
            break
        else:
            print("Invalid command. Please enter 'check' or 'exit'.")
