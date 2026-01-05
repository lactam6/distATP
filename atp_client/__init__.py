"""FinanceATP API Client - ATP通貨管理APIのGUIクライアント"""

from .atp_client import FinanceATPClient
import tkinter as tk

__version__ = "1.0.0"
__all__ = ["FinanceATPClient", "main"]


def main():
    """atp-client コマンドのエントリポイント"""
    root = tk.Tk()
    app = FinanceATPClient(root)
    root.mainloop()
