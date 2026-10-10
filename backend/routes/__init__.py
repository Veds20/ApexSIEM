from . import incidents
from . import soar

# Import the main router from routes.py in the parent directory (backend/)
import importlib.util
import os

_routes_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "routes.py")
_spec = importlib.util.spec_from_file_location("routes_module", _routes_path)
_routes_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_routes_module)

router = _routes_module.router

__all__ = ["router", "incidents", "soar"]