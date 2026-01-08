import os
import sys
import json
import inspect
from pathlib import Path
from typing import Dict, Optional, List, Tuple

from PySide6.QtCore import Qt, QThread, Signal, QObject
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QFileDialog,
    QMessageBox,
    QGroupBox,
    QFormLayout,
    QTableWidget,
    QTableWidgetItem,
    QAbstractItemView,
    QHeaderView,
    QProgressBar,
    QCheckBox,
)

from pypdf import PdfReader, PdfWriter

VERSION: str = "1.1.0"


# ---------------------------
# PyInstaller-friendly paths
# ---------------------------
def app_base_dir() -> Path:
    """
    Returns the base directory where resources live.
    - Source: directory of this file
    - PyInstaller: sys._MEIPASS
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS).resolve()  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent


# ---------------------------
# Crypto helpers
# ---------------------------
def encrypt_writer_compat(writer: PdfWriter, user_password: str, owner_password: Optional[str]) -> None:
    """
    Encrypt PdfWriter in a way that is compatible across pypdf versions.

    - Newer versions: encrypt(user_password=..., owner_password=..., algorithm="AES-256")
    - Older versions: encrypt(user_pwd=..., owner_pwd=..., encryption_algorithm="AES-256") or variations
    - Very old versions: no AES-256 selector available -> encrypt still works but algorithm may be weaker
    """
    if not owner_password:
        owner_password = user_password

    sig = inspect.signature(writer.encrypt)
    params = sig.parameters

    kwargs: dict = {}

    # Password argument names differ across versions
    if "user_password" in params:
        kwargs["user_password"] = user_password
        kwargs["owner_password"] = owner_password
    elif "user_pwd" in params:
        kwargs["user_pwd"] = user_password
        kwargs["owner_pwd"] = owner_password
    else:
        kwargs = {}

    # Algorithm selector differs across versions
    if "algorithm" in params:
        kwargs["algorithm"] = "AES-256"
    elif "encryption_algorithm" in params:
        kwargs["encryption_algorithm"] = "AES-256"

    # Try kwargs first
    try:
        if kwargs:
            writer.encrypt(**kwargs)
            return
    except TypeError:
        pass

    # Fallback positional (best effort)
    try:
        writer.encrypt(user_password, owner_password)  # type: ignore[arg-type]
    except Exception as e:
        raise RuntimeError(f"Could not apply encryption with current pypdf signature: {sig}") from e


def encrypt_pdf(input_path: str, output_path: str, user_password: str, owner_password: Optional[str] = None) -> None:
    reader = PdfReader(input_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    encrypt_writer_compat(writer, user_password=user_password, owner_password=owner_password)

    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(output_path, "wb") as f:
        writer.write(f)


# ---------------------------
# i18n via JSON files
# ---------------------------
class I18N:
    LANG_ES = "es"
    LANG_EN = "en"

    def __init__(self, lang: str = LANG_ES, base_dir: Optional[Path] = None) -> None:
        self.lang = lang
        self.base_dir = base_dir or app_base_dir()
        self._cache: Dict[str, Dict[str, str]] = {}
        self._strings = self._load_lang(self.lang)

    def _lang_path(self, lang: str) -> Path:
        return self.base_dir / "i18n" / f"{lang}.json"

    def _load_lang(self, lang: str) -> Dict[str, str]:
        if lang in self._cache:
            return self._cache[lang]

        p = self._lang_path(lang)
        if not p.exists():
            raise FileNotFoundError(f"Missing i18n file: {p}")

        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Invalid i18n JSON structure in {p} (expected object/dict)")

        normalized = {str(k): str(v) for k, v in data.items()}
        self._cache[lang] = normalized
        return normalized

    def set_lang(self, lang: str) -> None:
        self.lang = lang
        self._strings = self._load_lang(lang)

    def toggle(self) -> None:
        self.set_lang(self.LANG_EN if self.lang == self.LANG_ES else self.LANG_ES)

    def t(self, key: str) -> str:
        if key in self._strings:
            return self._strings[key]
        try:
            en = self._load_lang(self.LANG_EN)
            return en.get(key, key)
        except Exception:
            return key


# ---------------------------
# Worker (thread)
# ---------------------------
class BatchEncryptWorker(QObject):
    progress = Signal(int, int)  # done, total
    row_status = Signal(int, str)  # row, status_text
    row_output = Signal(int, str)  # row, output_path
    finished = Signal()
    failed = Signal(str)  # fatal error message (rare)

    def __init__(
        self,
        tasks: List[Tuple[int, str, str]],
        user_password: str,
        owner_password: Optional[str],
        overwrite: bool,
    ) -> None:
        super().__init__()
        self.tasks = tasks
        self.user_password = user_password
        self.owner_password = owner_password
        self.overwrite = overwrite
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:
        total = len(self.tasks)
        done = 0

        try:
            for row, in_path, out_path in self.tasks:
                if self._cancel:
                    self.row_status.emit(row, "CANCELLED")
                    continue

                try:
                    # Overwrite policy
                    if (not self.overwrite) and os.path.exists(out_path):
                        self.row_status.emit(row, "SKIPPED (exists)")
                    else:
                        self.row_status.emit(row, "PROCESSING…")
                        self.row_output.emit(row, out_path)
                        encrypt_pdf(in_path, out_path, self.user_password, self.owner_password)
                        self.row_status.emit(row, "OK")
                except Exception as e:
                    self.row_status.emit(row, f"ERROR: {e}")

                done += 1
                self.progress.emit(done, total)

        except Exception as e:
            self.failed.emit(str(e))
        finally:
            self.finished.emit()


# ---------------------------
# UI
# ---------------------------
class PdfEncryptor(QWidget):
    COL_INPUT = 0
    COL_OUTPUT = 1
    COL_STATUS = 2

    def __init__(self) -> None:
        super().__init__()

        # Default language: Spanish
        self.i18n = I18N(lang=I18N.LANG_ES)

        # Inputs: output dir + passwords
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setReadOnly(True)

        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)

        self.pass_confirm_edit = QLineEdit()
        self.pass_confirm_edit.setEchoMode(QLineEdit.Password)

        self.owner_pass_edit = QLineEdit()
        self.owner_pass_edit.setEchoMode(QLineEdit.Password)

        self.suffix_edit = QLineEdit()
        self.suffix_edit.setText("_protegido")  # will be updated by i18n apply

        self.chk_overwrite = QCheckBox()
        self.chk_overwrite.setChecked(False)

        # Buttons
        self.btn_add = QPushButton()
        self.btn_remove = QPushButton()
        self.btn_clear = QPushButton()

        self.btn_choose_outdir = QPushButton()
        self.btn_encrypt_all = QPushButton()
        self.btn_cancel = QPushButton()
        self.btn_cancel.setEnabled(False)

        # Language toggle
        self.btn_lang = QPushButton()
        self.btn_lang.setToolTip("Toggle language / Cambiar idioma")

        # Table
        self.table = QTableWidget(0, 3)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(self.COL_INPUT, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(self.COL_OUTPUT, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(self.COL_STATUS, QHeaderView.ResizeToContents)

        # Progress
        self.progress = QProgressBar()
        self.progress.setMinimum(0)
        self.progress.setValue(0)

        # Thread management
        self._thread: Optional[QThread] = None
        self._worker: Optional[BatchEncryptWorker] = None

        # Groups & labels
        self.files_group = QGroupBox()
        self.opts_group = QGroupBox()
        self.pass_group = QGroupBox()

        self.lbl_outdir = QLabel()
        self.lbl_suffix = QLabel()
        self.lbl_overwrite = QLabel()
        self.lbl_pass = QLabel()
        self.lbl_confirm = QLabel()
        self.lbl_owner = QLabel()

        self._build_ui()
        self._wire_events()
        self.apply_i18n()

    # ---- UI construction ----
    def _build_ui(self) -> None:
        self.setMinimumWidth(900)

        layout = QVBoxLayout(self)

        # Top bar (language)
        top_row = QHBoxLayout()
        top_row.addStretch(1)
        top_row.addWidget(self.btn_lang)
        layout.addLayout(top_row)

        # Files group
        files_layout = QVBoxLayout(self.files_group)

        btn_row = QHBoxLayout()
        btn_row.addWidget(self.btn_add)
        btn_row.addWidget(self.btn_remove)
        btn_row.addWidget(self.btn_clear)
        btn_row.addStretch(1)
        files_layout.addLayout(btn_row)

        files_layout.addWidget(self.table)

        layout.addWidget(self.files_group)

        # Options group
        opts_form = QFormLayout(self.opts_group)

        outdir_row = QHBoxLayout()
        outdir_row.addWidget(self.output_dir_edit, 1)
        outdir_row.addWidget(self.btn_choose_outdir)
        opts_form.addRow(self.lbl_outdir, outdir_row)

        opts_form.addRow(self.lbl_suffix, self.suffix_edit)

        overwrite_row = QHBoxLayout()
        overwrite_row.addWidget(self.chk_overwrite)
        overwrite_row.addStretch(1)
        opts_form.addRow(self.lbl_overwrite, overwrite_row)

        layout.addWidget(self.opts_group)

        # Passwords group
        pass_form = QFormLayout(self.pass_group)
        pass_form.addRow(self.lbl_pass, self.pass_edit)
        pass_form.addRow(self.lbl_confirm, self.pass_confirm_edit)
        pass_form.addRow(self.lbl_owner, self.owner_pass_edit)

        layout.addWidget(self.pass_group)

        # Bottom actions
        action_row = QHBoxLayout()
        action_row.addWidget(self.btn_encrypt_all)
        action_row.addWidget(self.btn_cancel)
        action_row.addStretch(1)
        layout.addLayout(action_row)

        layout.addWidget(self.progress)

    def _wire_events(self) -> None:
        self.btn_lang.clicked.connect(self.toggle_language)

        self.btn_add.clicked.connect(self.add_pdfs)
        self.btn_remove.clicked.connect(self.remove_selected)
        self.btn_clear.clicked.connect(self.clear_all)

        self.btn_choose_outdir.clicked.connect(self.choose_output_dir)

        self.btn_encrypt_all.clicked.connect(self.run_batch_encrypt)
        self.btn_cancel.clicked.connect(self.cancel_batch)

    # ---- i18n ----
    def apply_i18n(self) -> None:
        t = self.i18n.t

        self.setWindowTitle(f"{t('app_title')} v{VERSION}")

        self.files_group.setTitle(t("batch_group_files"))
        self.opts_group.setTitle(t("batch_group_options"))
        self.pass_group.setTitle(t("passwords_group"))

        self.btn_add.setText(t("btn_add_pdfs"))
        self.btn_remove.setText(t("btn_remove_selected"))
        self.btn_clear.setText(t("btn_clear_list"))

        self.table.setHorizontalHeaderLabels([t("col_input"), t("col_output"), t("col_status")])

        self.lbl_outdir.setText(t("output_dir"))
        self.btn_choose_outdir.setText(t("btn_choose_output_dir"))

        self.lbl_suffix.setText(t("output_suffix"))
        self.lbl_overwrite.setText(t("overwrite_label"))
        self.chk_overwrite.setText(t("overwrite_checkbox"))

        self.lbl_pass.setText(t("password_open"))
        self.lbl_confirm.setText(t("password_confirm"))
        self.lbl_owner.setText(t("password_owner"))
        self.owner_pass_edit.setPlaceholderText(t("owner_placeholder"))

        self.btn_encrypt_all.setText(t("btn_encrypt_all"))
        self.btn_cancel.setText(t("btn_cancel"))

        if self.i18n.lang == I18N.LANG_ES:
            self.btn_lang.setText(t("lang_button_to_en"))
            # default suffix in ES if user hasn't changed it
            if self.suffix_edit.text().strip() in ("", "_protected"):
                self.suffix_edit.setText("_protegido")
        else:
            self.btn_lang.setText(t("lang_button_to_es"))
            if self.suffix_edit.text().strip() in ("", "_protegido"):
                self.suffix_edit.setText("_protected")

    def toggle_language(self) -> None:
        self.i18n.toggle()
        self.apply_i18n()

    # ---- Table helpers ----
    def _add_row(self, in_path: str) -> int:
        row = self.table.rowCount()
        self.table.insertRow(row)

        # Input
        item_in = QTableWidgetItem(in_path)
        item_in.setToolTip(in_path)
        self.table.setItem(row, self.COL_INPUT, item_in)

        # Output placeholder
        item_out = QTableWidgetItem("")
        self.table.setItem(row, self.COL_OUTPUT, item_out)

        # Status
        item_st = QTableWidgetItem(self.i18n.t("status_pending"))
        self.table.setItem(row, self.COL_STATUS, item_st)

        return row

    def _set_status(self, row: int, status_text: str) -> None:
        # Map worker internal tokens to localized strings when possible
        t = self.i18n.t
        mapping = {
            "PROCESSING…": t("status_processing"),
            "OK": t("status_ok_short"),
            "CANCELLED": t("status_cancelled"),
            "SKIPPED (exists)": t("status_skipped_exists"),
        }
        show = mapping.get(status_text, status_text)
        it = self.table.item(row, self.COL_STATUS)
        if it is None:
            it = QTableWidgetItem(show)
            self.table.setItem(row, self.COL_STATUS, it)
        else:
            it.setText(show)

    def _set_output(self, row: int, out_path: str) -> None:
        it = self.table.item(row, self.COL_OUTPUT)
        if it is None:
            it = QTableWidgetItem(out_path)
            self.table.setItem(row, self.COL_OUTPUT, it)
        else:
            it.setText(out_path)
        it.setToolTip(out_path)

    def _selected_rows(self) -> List[int]:
        rows = set()
        for idx in self.table.selectionModel().selectedRows():
            rows.add(idx.row())
        return sorted(rows, reverse=True)

    # ---- Actions ----
    def add_pdfs(self) -> None:
        t = self.i18n.t

        paths, _ = QFileDialog.getOpenFileNames(
            self,
            t("dlg_pick_inputs_title"),
            "",
            "PDF (*.pdf)",
        )
        if not paths:
            return

        existing = set()
        for r in range(self.table.rowCount()):
            it = self.table.item(r, self.COL_INPUT)
            if it:
                existing.add(os.path.abspath(it.text().strip()))

        added = 0
        for p in paths:
            if not p:
                continue
            ap = os.path.abspath(p)
            if ap in existing:
                continue
            if not ap.lower().endswith(".pdf"):
                continue
            if not os.path.isfile(ap):
                continue
            self._add_row(ap)
            existing.add(ap)
            added += 1

        if added == 0:
            QMessageBox.information(self, t("info_title"), t("info_no_new_files"))

        # Suggest output dir from first file if empty
        if self.table.rowCount() > 0 and not self.output_dir_edit.text().strip():
            first = self.table.item(0, self.COL_INPUT).text()
            self.output_dir_edit.setText(str(Path(first).resolve().parent))

    def remove_selected(self) -> None:
        rows = self._selected_rows()
        for r in rows:
            self.table.removeRow(r)

    def clear_all(self) -> None:
        self.table.setRowCount(0)
        self.progress.setValue(0)

    def choose_output_dir(self) -> None:
        t = self.i18n.t
        start = self.output_dir_edit.text().strip() or str(Path.home())
        path = QFileDialog.getExistingDirectory(self, t("dlg_pick_output_dir_title"), start)
        if not path:
            return
        self.output_dir_edit.setText(path)

    def _error(self, title: str, msg: str) -> None:
        QMessageBox.critical(self, title, msg)

    def _info(self, title: str, msg: str) -> None:
        QMessageBox.information(self, title, msg)

    def _validate_batch(self) -> Optional[Tuple[List[Tuple[int, str, str]], str, Optional[str], bool]]:
        t = self.i18n.t

        if self.table.rowCount() == 0:
            self._error(t("err_no_files_title"), t("err_no_files_msg"))
            return None

        out_dir = self.output_dir_edit.text().strip()
        if not out_dir:
            self._error(t("err_missing_output_dir_title"), t("err_missing_output_dir_msg"))
            return None

        # Ensure output dir exists
        try:
            Path(out_dir).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self._error(t("err_missing_output_dir_title"), t("err_output_dir_create_failed").format(error=e))
            return None

        suffix = self.suffix_edit.text().strip()
        if not suffix:
            self._error(t("err_suffix_title"), t("err_suffix_msg"))
            return None

        p1 = self.pass_edit.text()
        p2 = self.pass_confirm_edit.text()
        owner = self.owner_pass_edit.text().strip() or None
        overwrite = self.chk_overwrite.isChecked()

        if not p1:
            self._error(t("err_empty_pass_title"), t("err_empty_pass_msg"))
            return None
        if p1 != p2:
            self._error(t("err_mismatch_title"), t("err_mismatch_msg"))
            return None

        # Soft warning for short password
        if len(p1) < 12:
            r = QMessageBox.warning(
                self,
                t("warn_short_title"),
                t("warn_short_msg_batch"),
                QMessageBox.Yes | QMessageBox.No,
            )
            if r != QMessageBox.Yes:
                return None

        tasks: List[Tuple[int, str, str]] = []
        used_outputs = set()

        for row in range(self.table.rowCount()):
            in_item = self.table.item(row, self.COL_INPUT)
            if not in_item:
                continue
            in_path = in_item.text().strip()
            if not in_path or not os.path.isfile(in_path):
                self._set_status(row, f"ERROR: {t('status_missing_input')}")
                continue

            stem = Path(in_path).stem
            out_path = str(Path(out_dir) / f"{stem}{suffix}.pdf")

            # Avoid same-file overwrite and collisions
            if os.path.abspath(in_path) == os.path.abspath(out_path):
                self._set_status(row, f"ERROR: {t('status_output_same_as_input')}")
                continue

            # If multiple inputs produce same output, disambiguate
            final_out = out_path
            counter = 2
            while final_out.lower() in used_outputs:
                final_out = str(Path(out_dir) / f"{stem}{suffix}_{counter}.pdf")
                counter += 1

            used_outputs.add(final_out.lower())

            self._set_output(row, final_out)
            self._set_status(row, t("status_pending"))
            tasks.append((row, in_path, final_out))

        if not tasks:
            self._error(t("err_no_valid_tasks_title"), t("err_no_valid_tasks_msg"))
            return None

        return tasks, p1, owner, overwrite

    def run_batch_encrypt(self) -> None:
        if self._thread is not None:
            return

        validated = self._validate_batch()
        if not validated:
            return

        tasks, user_pass, owner_pass, overwrite = validated

        # UI state
        self.btn_encrypt_all.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_add.setEnabled(False)
        self.btn_remove.setEnabled(False)
        self.btn_clear.setEnabled(False)
        self.btn_choose_outdir.setEnabled(False)

        self.progress.setMaximum(len(tasks))
        self.progress.setValue(0)

        # Thread + worker
        self._thread = QThread(self)
        self._worker = BatchEncryptWorker(tasks, user_pass, owner_pass, overwrite)
        self._worker.moveToThread(self._thread)

        # Connect signals
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.row_status.connect(self._on_row_status)
        self._worker.row_output.connect(self._on_row_output)
        self._worker.failed.connect(self._on_fatal_error)
        self._worker.finished.connect(self._on_finished)

        # Ensure cleanup
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup_thread)

        self._thread.start()

    def cancel_batch(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
        self.btn_cancel.setEnabled(False)

    # ---- Worker signal handlers ----
    def _on_progress(self, done: int, total: int) -> None:
        self.progress.setMaximum(total)
        self.progress.setValue(done)

    def _on_row_status(self, row: int, status_text: str) -> None:
        self._set_status(row, status_text)

    def _on_row_output(self, row: int, out_path: str) -> None:
        self._set_output(row, out_path)

    def _on_fatal_error(self, msg: str) -> None:
        t = self.i18n.t
        self._error(t("err_encrypt_title"), t("err_encrypt_fatal").format(error=msg))

    def _on_finished(self) -> None:
        t = self.i18n.t

        # Summarize results
        ok = 0
        err = 0
        skipped = 0
        cancelled = 0

        for row in range(self.table.rowCount()):
            st = self.table.item(row, self.COL_STATUS)
            if not st:
                continue
            s = st.text()
            if s == t("status_ok_short"):
                ok += 1
            elif s == t("status_skipped_exists"):
                skipped += 1
            elif s == t("status_cancelled"):
                cancelled += 1
            elif s.startswith("ERROR") or s.startswith("Error") or "ERROR:" in s:
                err += 1

        self._info(
            t("info_done_title"),
            t("info_done_batch_msg").format(ok=ok, skipped=skipped, err=err, cancelled=cancelled),
        )

        # Restore UI state
        self.btn_encrypt_all.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_add.setEnabled(True)
        self.btn_remove.setEnabled(True)
        self.btn_clear.setEnabled(True)
        self.btn_choose_outdir.setEnabled(True)

    def _cleanup_thread(self) -> None:
        self._thread = None
        self._worker = None


def main() -> int:
    app = QApplication(sys.argv)
    w = PdfEncryptor()
    w.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
