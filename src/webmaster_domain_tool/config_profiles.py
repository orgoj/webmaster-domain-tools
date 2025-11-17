"""Configuration profiles management for named configurations."""

import json
import logging
from pathlib import Path

from pydantic import ValidationError

from .config import Config, load_config

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

    def save_profile(self, name: str, config: Config) -> None:
        """
        Save configuration as a named profile.

        Args:
            name: Profile name
            config: Configuration to save

        Raises:
            ValueError: If profile name is invalid
        """
        if not name or "/" in name or "\\" in name:
            raise ValueError(f"Invalid profile name: {name}")

        profile_path = self.profiles_dir / f"{name}.json"

        # Convert config to dict
        config_dict = config.model_dump(mode="json")

        # Save to JSON file
        with open(profile_path, "w") as f:
            json.dump(config_dict, f, indent=2)

        logger.info(f"Saved profile: {name} to {profile_path}")

    def load_profile(self, name: str) -> Config:
        """
        Load configuration from named profile.

        Args:
            name: Profile name

        Returns:
            Loaded configuration

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

            # Validate and create Config
            config = Config(**config_dict)
            logger.info(f"Loaded profile: {name}")
            return config

        except (json.JSONDecodeError, ValidationError) as e:
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

    def get_or_create_default(self) -> Config:
        """
        Get default profile or create if doesn't exist.

        Returns:
            Default configuration profile
        """
        if self.profile_exists("default"):
            return self.load_profile("default")
        else:
            # Create default from current config
            config = load_config()
            self.save_profile("default", config)
            return config
