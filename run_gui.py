"""Launcher script for PyInstaller packaging.

PyInstaller runs scripts as standalone files, which breaks Python's
package-relative imports (``from .cipher import ...``). This tiny
launcher imports the GUI via the installed ``crypto_tool`` package,
so all relative imports resolve correctly at freeze time.
"""
from crypto_tool.gui import main

if __name__ == "__main__":
    main()
