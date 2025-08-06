"""
Internationalization Support
Multi-language support for CLI interface
"""

import json
from pathlib import Path
from typing import Dict, Optional
import locale


class I18nManager:
    """Manages internationalization for the CLI"""
    
    def __init__(self):
        self.current_language = self._detect_system_language()
        self.translations: Dict[str, Dict[str, str]] = {}
        self.fallback_language = "en"
        self._load_translations()
    
    def _detect_system_language(self) -> str:
        """Detect system language"""
        try:
            system_locale = locale.getdefaultlocale()[0]
            if system_locale:
                # Extract language code (e.g., "en" from "en_US")
                return system_locale.split('_')[0].lower()
        except:
            pass
        return "en"
    
    def _load_translations(self):
        """Load translation files"""
        # For now, we'll use embedded translations
        # In production, these would be loaded from JSON files
        
        self.translations = {
            "en": {
                "welcome": "Welcome to Image Converter CLI",
                "converting": "Converting",
                "complete": "Complete",
                "error": "Error",
                "success": "Success",
                "failed": "Failed",
                "cancelled": "Cancelled",
                "help": "Help",
                "version": "Version",
                "file_not_found": "File not found",
                "invalid_format": "Invalid format",
                "conversion_complete": "Conversion complete",
                "batch_processing": "Processing batch",
            },
            "es": {
                "welcome": "Bienvenido a Image Converter CLI",
                "converting": "Convirtiendo",
                "complete": "Completo",
                "error": "Error",
                "success": "Éxito",
                "failed": "Falló",
                "cancelled": "Cancelado",
                "help": "Ayuda",
                "version": "Versión",
                "file_not_found": "Archivo no encontrado",
                "invalid_format": "Formato inválido",
                "conversion_complete": "Conversión completa",
                "batch_processing": "Procesando lote",
            },
            "fr": {
                "welcome": "Bienvenue dans Image Converter CLI",
                "converting": "Conversion",
                "complete": "Terminé",
                "error": "Erreur",
                "success": "Succès",
                "failed": "Échoué",
                "cancelled": "Annulé",
                "help": "Aide",
                "version": "Version",
                "file_not_found": "Fichier non trouvé",
                "invalid_format": "Format invalide",
                "conversion_complete": "Conversion terminée",
                "batch_processing": "Traitement par lots",
            },
            "de": {
                "welcome": "Willkommen bei Image Converter CLI",
                "converting": "Konvertierung",
                "complete": "Abgeschlossen",
                "error": "Fehler",
                "success": "Erfolg",
                "failed": "Fehlgeschlagen",
                "cancelled": "Abgebrochen",
                "help": "Hilfe",
                "version": "Version",
                "file_not_found": "Datei nicht gefunden",
                "invalid_format": "Ungültiges Format",
                "conversion_complete": "Konvertierung abgeschlossen",
                "batch_processing": "Stapelverarbeitung",
            },
            "zh": {
                "welcome": "欢迎使用图像转换器CLI",
                "converting": "转换中",
                "complete": "完成",
                "error": "错误",
                "success": "成功",
                "failed": "失败",
                "cancelled": "已取消",
                "help": "帮助",
                "version": "版本",
                "file_not_found": "文件未找到",
                "invalid_format": "无效格式",
                "conversion_complete": "转换完成",
                "batch_processing": "批处理中",
            },
            "ja": {
                "welcome": "画像変換CLIへようこそ",
                "converting": "変換中",
                "complete": "完了",
                "error": "エラー",
                "success": "成功",
                "failed": "失敗",
                "cancelled": "キャンセル",
                "help": "ヘルプ",
                "version": "バージョン",
                "file_not_found": "ファイルが見つかりません",
                "invalid_format": "無効な形式",
                "conversion_complete": "変換完了",
                "batch_processing": "バッチ処理中",
            }
        }
    
    def set_language(self, language: str):
        """Set the current language"""
        if language in self.translations:
            self.current_language = language
        else:
            # Fallback to English if language not supported
            self.current_language = self.fallback_language
    
    def get(self, key: str, **kwargs) -> str:
        """Get translated string"""
        # Get translation for current language
        if self.current_language in self.translations:
            text = self.translations[self.current_language].get(key)
            if text:
                # Format with any provided arguments
                return text.format(**kwargs) if kwargs else text
        
        # Fallback to English
        if self.fallback_language in self.translations:
            text = self.translations[self.fallback_language].get(key)
            if text:
                return text.format(**kwargs) if kwargs else text
        
        # Return key if no translation found
        return key
    
    def get_available_languages(self) -> Dict[str, str]:
        """Get available languages"""
        return {
            "en": "English",
            "es": "Español",
            "fr": "Français",
            "de": "Deutsch",
            "zh": "中文",
            "ja": "日本語"
        }


# Global i18n manager
_i18n_manager = I18nManager()


def set_language(language: str):
    """Set the interface language"""
    _i18n_manager.set_language(language)


def t(key: str, **kwargs) -> str:
    """Translate a string (shorthand for get)"""
    return _i18n_manager.get(key, **kwargs)


def get_language() -> str:
    """Get current language"""
    return _i18n_manager.current_language


def get_available_languages() -> Dict[str, str]:
    """Get available languages"""
    return _i18n_manager.get_available_languages()