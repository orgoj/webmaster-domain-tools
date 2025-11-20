"""Configuration profiles management for named configurations."""

import json
import logging
from pathlib import Path

from .gui_config_adapter import GUIConfigAdapter

logger = logging.getLogger(__name__)


class ConfigProfileManager:
    """Manage named configuration profiles."""

    def __init__(self, profiles_dir: Path | None = None) -> None:
        """
        Initialize profile manager.

        Args:
            profiles_dir: Directory for storing profiles (default: ~/.config/webmaster-domain-tool/profiles/)
        """
        if profiles_dir is None:
            config_home = Path.home() / ".config" / "webmaster-domain-tool"
            self.profiles_dir = config_home / "profiles"
        else:
            self.profiles_dir = profiles_dir

        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Config profiles directory: {self.profiles_dir}")

    def list_profiles(self) -> list[str]:
        """
        List all available profile names.

        Returns:
            List of profile names (without .json extension)
        """
        profiles = []
        for file in self.profiles_dir.glob("*.json"):
            profiles.append(file.stem)
        return sorted(profiles)

    def save_profile(self, name: str, config_adapter: GUIConfigAdapter) -> None:
        """
        Save configuration as a named profile.

        Args:
            name: Profile name
            config_adapter: Configuration adapter to save

        Raises:
            ValueError: If profile name is invalid
        """
        if not name or "/" in name or "\\" in name:
            raise ValueError(f"Invalid profile name: {name}")

        profile_path = self.profiles_dir / f"{name}.json"

        # Convert config to dict
        config_dict = config_adapter.to_dict()

        # Save to JSON file
        with open(profile_path, "w") as f:
            json.dump(config_dict, f, indent=2)

        logger.info(f"Saved profile: {name} to {profile_path}")

    def load_profile(self, name: str) -> GUIConfigAdapter:
        """
        Load configuration from named profile.

        Args:
            name: Profile name

        Returns:
            Loaded configuration adapter

        Raises:
            FileNotFoundError: If profile doesn't exist
            ValueError: If profile is invalid
        """
        profile_path = self.profiles_dir / f"{name}.json"

        if not profile_path.exists():
            raise FileNotFoundError(f"Profile not found: {name}")

        try:
            with open(profile_path) as f:
                config_dict = json.load(f)

            # Create adapter and load data
            adapter = GUIConfigAdapter()
            adapter.from_dict(config_dict)
            logger.info(f"Loaded profile: {name}")
            return adapter

        except (json.JSONDecodeError, Exception) as e:
            raise ValueError(f"Invalid profile {name}: {e}") from e

    def delete_profile(self, name: str) -> None:
        """
        Delete a named profile.

        Args:
            name: Profile name

        Raises:
            FileNotFoundError: If profile doesn't exist
        """
        profile_path = self.profiles_dir / f"{name}.json"

        if not profile_path.exists():
            raise FileNotFoundError(f"Profile not found: {name}")

        profile_path.unlink()
        logger.info(f"Deleted profile: {name}")

    def profile_exists(self, name: str) -> bool:
        """
        Check if profile exists.

        Args:
            name: Profile name

        Returns:
            True if profile exists
        """
        profile_path = self.profiles_dir / f"{name}.json"
        return profile_path.exists()

    def get_or_create_default(self) -> GUIConfigAdapter:
        """
        Get default configuration (always from code, never saved).

        The default config should always come from code (default_config.toml),
        not from saved profiles. This ensures schema changes are properly picked up.

        If an old "default" profile exists, it will be deleted (migration).

        Returns:
            Fresh default configuration adapter from code
        """
        # Migration: Delete old "default" profile if it exists
        if self.profile_exists("default"):
            logger.info("Deleting old 'default' profile (migration to code-based defaults)")
            try:
                self.delete_profile("default")
            except Exception as e:
                logger.warning(f"Failed to delete old 'default' profile: {e}")

        # Always return fresh config from code
        return GUIConfigAdapter()
