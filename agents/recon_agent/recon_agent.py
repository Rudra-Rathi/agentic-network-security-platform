"""
Recon Agent||
responsible for network and host discovery only.
Produces structured recon JSON artifact
"""

from pathlib import Path 
from datetime import datetime
import json
import uuid


def load_recon_template():
    template_path = Path("docs/recon_data_model.json")
    with open(template_path, "r") as f:
        return json.load(f)
    
def initialize_metadata(recon_data, target):
    recon_data["scan_metadata"]["scan_id"] = str(uuid.uuid4())
    recon_data["scan_metadata"] ["target"] = target
    recon_data["scan_metadata"] ["timestamp"] = datetime.utcnow().isoformat + "Z"
    recon_data["scan_metadata"] ["initiated_by"] = "user"
    
