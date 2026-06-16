import sys
import os
import time
from PySide6.QtCore import QCoreApplication, QTimer

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from torcall.core.tor_manager import TorManager, TorStatus
from torcall.utils.logger import log

def test_bootstrap():
    app = QCoreApplication(sys.argv)
    
    tor = TorManager()
    
    def on_status_changed(status):
        print(f"Tor Status Changed: {status}")
        if status == TorStatus.READY:
            print("Tor is fully bootstrapped and ready! Now creating hidden service...")
            tor.create_hidden_service()
        elif status == TorStatus.ERROR:
            print("Tor encountered an error!")
            QTimer.singleShot(1000, stop_and_exit)
            
    def on_progress(pct):
        print(f"Bootstrap progress: {pct}%")
        
    def on_address(addr):
        print(f"Onion address generated: {addr}")
        print("Success! Hidden service is published and active.")
        QTimer.singleShot(1000, stop_and_exit)
        
    def on_error(msg):
        print(f"Error occurred: {msg}")
        
    def stop_and_exit():
        print("Stopping Tor...")
        tor.stop()
        app.quit()
        
    tor.status_changed.connect(on_status_changed)
    tor.bootstrap_progress.connect(on_progress)
    tor.address_changed.connect(on_address)
    tor.error_occurred.connect(on_error)
    
    print("Starting TorManager...")
    tor.start()
    
    # Timeout if it takes too long (e.g. 3 minutes)
    QTimer.singleShot(180000, lambda: (print("Timeout waiting for bootstrap/hidden service!"), stop_and_exit()))
    
    sys.exit(app.exec())

if __name__ == "__main__":
    test_bootstrap()
