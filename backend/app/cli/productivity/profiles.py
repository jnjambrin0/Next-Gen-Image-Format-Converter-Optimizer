"""
Configuration Profiles System
Manage different configuration profiles for various use cases
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.cli.config import CLIConfig, get_config, get_config_dir


@dataclass
class Profile:
    """Configuration profile"""

    name: str
    description: str
    parent: Optional[str] = None
    settings: Dict[str, Any] = None
    overrides: Dict[str, Dict[str, Any]] = None
    created_at: str = None
    updated_at: str = None
    is_builtin: bool = False

    def __post_init__(self):
        if self.settings is None:
            self.settings = {}
        if self.overrides is None:
            self.overrides = {}
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()
        if self.updated_at is None:
            self.updated_at = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "Profile":
        """Create from dictionary"""
        return cls(**data)

    def apply_to_config(self, config: CLIConfig) -> CLIConfig:
        """
        Apply profile settings to configuration

        Args:
            config: Base configuration

        Returns:
            Modified configuration
        """
        # Apply general settings
        for key, value in self.settings.items():
            if hasattr(config, key):
                setattr(config, key, value)

        return config

    def get_effective_settings(
        self, parent_profile: Optional["Profile"] = None
    ) -> Dict[str, Any]:
        """
        Get effective settings including parent inheritance

        Args:
            parent_profile: Parent profile if any

        Returns:
            Merged settings
        """
        if parent_profile:
            # Start with parent settings
            effective = parent_profile.get_effective_settings()
            # Override with this profile's settings
            effective.update(self.settings)
            return effective
        else:
            return self.settings.copy()


class ProfileManager:
    """Manage configuration profiles"""

    # Built-in profiles
    BUILTIN_PROFILES = {
        "web-optimized": Profile(
            name="web-optimized",
            description="Optimized for web delivery with smaller file sizes",
            settings={
                "default_output_format": "webp",
                "default_quality": 85,
                "preserve_metadata": False,
                "default_preset": "web",
            },
            overrides={
                "convert": {
                    "max_width": 1920,
                    "max_height": 1080,
                    "strip_metadata": True,
                },
                "batch": {"workers": 4, "show_progress": True},
            },
            is_builtin=True,
        ),
        "print-quality": Profile(
            name="print-quality",
            description="High quality settings for print production",
            settings={
                "default_output_format": "tiff",
                "default_quality": 100,
                "preserve_metadata": True,
                "default_preset": "print",
            },
            overrides={
                "convert": {
                    "min_dpi": 300,
                    "color_profile": "sRGB",
                    "strip_metadata": False,
                },
                "optimize": {"lossless": True},
            },
            is_builtin=True,
        ),
        "fast-processing": Profile(
            name="fast-processing",
            description="Fastest processing with acceptable quality",
            settings={
                "default_output_format": "jpeg",
                "default_quality": 75,
                "preserve_metadata": False,
                "show_progress": False,
            },
            overrides={
                "batch": {"workers": "auto", "skip_errors": True},
                "convert": {"fast_mode": True, "skip_validation": True},
            },
            is_builtin=True,
        ),
        "archive": Profile(
            name="archive",
            description="Long-term archival with lossless compression",
            settings={
                "default_output_format": "png",
                "default_quality": 100,
                "preserve_metadata": True,
                "default_preset": "archive",
            },
            overrides={
                "convert": {"compression": "lossless", "verify_output": True},
                "batch": {"create_manifest": True, "verify_checksums": True},
            },
            is_builtin=True,
        ),
        "thumbnail": Profile(
            name="thumbnail",
            description="Generate small thumbnails for previews",
            settings={
                "default_output_format": "webp",
                "default_quality": 70,
                "preserve_metadata": False,
            },
            overrides={
                "convert": {
                    "max_width": 400,
                    "max_height": 400,
                    "maintain_aspect": True,
                    "strip_metadata": True,
                },
                "optimize": {"target_size": "50KB"},
            },
            is_builtin=True,
        ),
    }

    def __init__(self):
        """Initialize profile manager"""
        self.profiles_dir = get_config_dir() / "profiles"
        self.profiles_dir.mkdir(parents=True, exist_ok=True)

        # Load user profiles
        self.user_profiles = self._load_user_profiles()

        # Current active profile
        self.active_profile: Optional[str] = None

    def _load_user_profiles(self) -> Dict[str, Profile]:
        """Load user-defined profiles from disk"""
        profiles = {}

        for profile_file in self.profiles_dir.glob("*.json"):
            try:
                with open(profile_file, "r") as f:
                    data = json.load(f)
                    profile = Profile.from_dict(data)
                    profiles[profile.name] = profile
            except (json.JSONDecodeError, KeyError, IOError):
                # Skip invalid profile files
                continue

        return profiles

    def _save_user_profile(self, profile: Profile):
        """Save user profile to disk"""
        profile_file = self.profiles_dir / f"{profile.name}.json"
        profile.updated_at = datetime.now().isoformat()

        with open(profile_file, "w") as f:
            json.dump(profile.to_dict(), f, indent=2)

    def get_profile(self, name: str) -> Optional[Profile]:
        """
        Get profile by name

        Args:
            name: Profile name

        Returns:
            Profile or None if not found
        """
        # Check built-in profiles first
        if name in self.BUILTIN_PROFILES:
            return self.BUILTIN_PROFILES[name]

        # Check user profiles
        return self.user_profiles.get(name)

    def list_profiles(self, include_builtin: bool = True) -> List[Profile]:
        """
        List all available profiles

        Args:
            include_builtin: Whether to include built-in profiles

        Returns:
            List of profiles
        """
        profiles = []

        if include_builtin:
            profiles.extend(self.BUILTIN_PROFILES.values())

        profiles.extend(self.user_profiles.values())

        # Sort by name
        profiles.sort(key=lambda p: p.name)

        return profiles

    def create_profile(
        self,
        name: str,
        description: str,
        settings: Dict[str, Any],
        parent: Optional[str] = None,
        overrides: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Profile:
        """
        Create a new user profile

        Args:
            name: Profile name
            description: Profile description
            settings: Profile settings
            parent: Optional parent profile name
            overrides: Command-specific overrides

        Returns:
            Created profile

        Raises:
            ValueError: If profile name already exists
        """
        # Check if name already exists
        if name in self.BUILTIN_PROFILES or name in self.user_profiles:
            raise ValueError(f"Profile '{name}' already exists")

        # Validate parent if specified
        if parent and not self.get_profile(parent):
            raise ValueError(f"Parent profile '{parent}' not found")

        # Create profile
        profile = Profile(
            name=name,
            description=description,
            settings=settings,
            parent=parent,
            overrides=overrides or {},
            is_builtin=False,
        )

        # Save to disk
        self._save_user_profile(profile)

        # Add to user profiles
        self.user_profiles[name] = profile

        return profile

    def update_profile(
        self,
        name: str,
        description: Optional[str] = None,
        settings: Optional[Dict[str, Any]] = None,
        overrides: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Profile:
        """
        Update an existing user profile

        Args:
            name: Profile name
            description: New description (optional)
            settings: New settings (optional)
            overrides: New overrides (optional)

        Returns:
            Updated profile

        Raises:
            ValueError: If profile not found or is built-in
        """
        # Cannot update built-in profiles
        if name in self.BUILTIN_PROFILES:
            raise ValueError(f"Cannot update built-in profile '{name}'")

        # Get existing profile
        if name not in self.user_profiles:
            raise ValueError(f"Profile '{name}' not found")

        profile = self.user_profiles[name]

        # Update fields
        if description is not None:
            profile.description = description
        if settings is not None:
            profile.settings.update(settings)
        if overrides is not None:
            profile.overrides.update(overrides)

        # Save to disk
        self._save_user_profile(profile)

        return profile

    def delete_profile(self, name: str) -> bool:
        """
        Delete a user profile

        Args:
            name: Profile name

        Returns:
            True if deleted

        Raises:
            ValueError: If profile is built-in
        """
        # Cannot delete built-in profiles
        if name in self.BUILTIN_PROFILES:
            raise ValueError(f"Cannot delete built-in profile '{name}'")

        if name not in self.user_profiles:
            return False

        # Delete file
        profile_file = self.profiles_dir / f"{name}.json"
        profile_file.unlink(missing_ok=True)

        # Remove from memory
        del self.user_profiles[name]

        # If this was the active profile, clear it
        if self.active_profile == name:
            self.active_profile = None

        return True

    def switch_profile(self, name: Optional[str]) -> Optional[Profile]:
        """
        Switch to a different profile

        Args:
            name: Profile name (None to clear)

        Returns:
            Activated profile or None

        Raises:
            ValueError: If profile not found
        """
        if name is None:
            self.active_profile = None
            return None

        profile = self.get_profile(name)
        if not profile:
            raise ValueError(f"Profile '{name}' not found")

        self.active_profile = name
        return profile

    def get_active_profile(self) -> Optional[Profile]:
        """Get currently active profile"""
        if self.active_profile:
            return self.get_profile(self.active_profile)
        return None

    def apply_active_profile(self, config: CLIConfig) -> CLIConfig:
        """
        Apply active profile to configuration

        Args:
            config: Base configuration

        Returns:
            Modified configuration
        """
        profile = self.get_active_profile()
        if profile:
            # Apply parent profile first if any
            if profile.parent:
                parent = self.get_profile(profile.parent)
                if parent:
                    config = parent.apply_to_config(config)

            # Apply this profile
            config = profile.apply_to_config(config)

        return config

    def export_profile(self, name: str, output_file: Path) -> bool:
        """
        Export profile to file

        Args:
            name: Profile name
            output_file: Output file path

        Returns:
            Success status
        """
        profile = self.get_profile(name)
        if not profile:
            return False

        try:
            with open(output_file, "w") as f:
                json.dump(profile.to_dict(), f, indent=2)
            return True
        except IOError:
            return False

    def import_profile(
        self, input_file: Path, rename: Optional[str] = None
    ) -> Optional[Profile]:
        """
        Import profile from file

        Args:
            input_file: Input file path
            rename: Optional new name for imported profile

        Returns:
            Imported profile or None
        """
        try:
            with open(input_file, "r") as f:
                data = json.load(f)

            profile = Profile.from_dict(data)
            profile.is_builtin = False  # Imported profiles are always user profiles

            # Rename if requested
            if rename:
                profile.name = rename

            # Check for name conflicts
            if (
                profile.name in self.BUILTIN_PROFILES
                or profile.name in self.user_profiles
            ):
                # Auto-rename with timestamp
                profile.name = (
                    f"{profile.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                )

            # Save profile
            self._save_user_profile(profile)
            self.user_profiles[profile.name] = profile

            return profile
        except (json.JSONDecodeError, KeyError, IOError):
            return None

    def clone_profile(
        self, source_name: str, new_name: str, new_description: Optional[str] = None
    ) -> Profile:
        """
        Clone an existing profile

        Args:
            source_name: Source profile name
            new_name: New profile name
            new_description: Optional new description

        Returns:
            Cloned profile

        Raises:
            ValueError: If source not found or new name exists
        """
        source = self.get_profile(source_name)
        if not source:
            raise ValueError(f"Source profile '{source_name}' not found")

        if new_name in self.BUILTIN_PROFILES or new_name in self.user_profiles:
            raise ValueError(f"Profile '{new_name}' already exists")

        # Create clone
        cloned = Profile(
            name=new_name,
            description=new_description or f"Clone of {source.description}",
            parent=source.parent,
            settings=source.settings.copy(),
            overrides={k: v.copy() for k, v in source.overrides.items()},
            is_builtin=False,
        )

        # Save clone
        self._save_user_profile(cloned)
        self.user_profiles[new_name] = cloned

        return cloned
