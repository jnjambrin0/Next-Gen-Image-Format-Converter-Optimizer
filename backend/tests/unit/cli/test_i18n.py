"""
Unit tests for internationalization
"""

import pytest
from unittest.mock import Mock, patch
import locale

from app.cli.utils.i18n import I18nManager


class TestI18nManager:
    """Test internationalization manager"""
    
    def test_i18n_manager_init(self):
        """Test i18n manager initialization"""
        with patch('app.cli.utils.i18n.locale.getdefaultlocale') as mock_locale:
            mock_locale.return_value = ('en_US', 'UTF-8')
            
            manager = I18nManager()
            
            assert manager.current_language == "en"
            assert manager.fallback_language == "en"
            assert len(manager.translations) > 0
    
    def test_detect_system_language(self):
        """Test system language detection"""
        manager = I18nManager()
        
        with patch('locale.getdefaultlocale') as mock_locale:
            # Test English
            mock_locale.return_value = ('en_US', 'UTF-8')
            lang = manager._detect_system_language()
            assert lang == "en"
            
            # Test Spanish
            mock_locale.return_value = ('es_ES', 'UTF-8')
            lang = manager._detect_system_language()
            assert lang == "es"
            
            # Test Chinese
            mock_locale.return_value = ('zh_CN', 'UTF-8')
            lang = manager._detect_system_language()
            assert lang == "zh"
            
            # Test when locale returns None
            mock_locale.return_value = (None, None)
            lang = manager._detect_system_language()
            assert lang == "en"
            
            # Test when locale raises exception
            mock_locale.side_effect = Exception("Locale error")
            lang = manager._detect_system_language()
            assert lang == "en"
    
    def test_set_language(self):
        """Test setting language"""
        manager = I18nManager()
        
        # Set to valid language
        manager.set_language("es")
        assert manager.current_language == "es"
        
        manager.set_language("fr")
        assert manager.current_language == "fr"
        
        # Set to invalid language (should fallback to English)
        manager.set_language("invalid")
        assert manager.current_language == "en"
    
    def test_get_translation(self):
        """Test getting translations"""
        manager = I18nManager()
        
        # Test English
        manager.set_language("en")
        assert manager.get("welcome") == "Welcome to Image Converter CLI"
        assert manager.get("converting") == "Converting"
        assert manager.get("error") == "Error"
        
        # Test Spanish
        manager.set_language("es")
        assert manager.get("welcome") == "Bienvenido a Image Converter CLI"
        assert manager.get("converting") == "Convirtiendo"
        assert manager.get("error") == "Error"
        
        # Test French
        manager.set_language("fr")
        assert manager.get("welcome") == "Bienvenue dans Image Converter CLI"
        assert manager.get("converting") == "Conversion"
        assert manager.get("error") == "Erreur"
    
    def test_get_translation_with_formatting(self):
        """Test getting translations with formatting"""
        manager = I18nManager()
        
        # Add a translation with placeholder
        manager.translations["en"]["test_format"] = "Processing {filename}"
        
        manager.set_language("en")
        result = manager.get("test_format", filename="image.jpg")
        assert result == "Processing image.jpg"
    
    def test_get_missing_translation(self):
        """Test getting missing translation returns key"""
        manager = I18nManager()
        
        manager.set_language("en")
        result = manager.get("non_existent_key")
        assert result == "non_existent_key"
    
    def test_fallback_to_english(self):
        """Test fallback to English for missing translations"""
        manager = I18nManager()
        
        # Remove a translation from Spanish
        manager.translations["es"].pop("conversion_complete", None)
        
        manager.set_language("es")
        result = manager.get("conversion_complete")
        
        # Should fallback to English
        assert result == "Conversion complete"
    
    def test_get_available_languages(self):
        """Test getting available languages"""
        manager = I18nManager()
        
        languages = manager.get_available_languages()
        
        assert "en" in languages
        assert languages["en"] == "English"
        assert "es" in languages
        assert languages["es"] == "Español"
        assert "fr" in languages
        assert languages["fr"] == "Français"
        assert "de" in languages
        assert languages["de"] == "Deutsch"
        assert "zh" in languages
        assert languages["zh"] == "中文"
        assert "ja" in languages
        assert languages["ja"] == "日本語"
    
    def test_all_languages_have_basic_translations(self):
        """Test that all languages have basic required translations"""
        manager = I18nManager()
        
        required_keys = [
            "welcome", "converting", "complete", "error", 
            "success", "failed", "cancelled", "help", "version"
        ]
        
        for lang_code in ["en", "es", "fr", "de", "zh", "ja"]:
            for key in required_keys:
                assert key in manager.translations[lang_code], \
                    f"Missing key '{key}' in language '{lang_code}'"