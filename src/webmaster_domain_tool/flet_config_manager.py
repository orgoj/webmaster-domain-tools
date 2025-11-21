"""Flet client storage based configuration profile manager."""

import json
import logging
from typing import TYPE_CHECKING

from .gui_config_adapter import GUIConfigAdapter

if TYPE_CHECKING:
    import flet as ft

logger = logging.getLogger(__name__)


class FletConfigProfileManager:
    """Manage configuration profiles using Flet client storage."""

    # Key prefix for namespacing (prevents conflicts with other apps)
    KEY_PREFIX = "wdt.profile."
    PROFILE_LIST_KEY = "wdt.profiles.list"
    LAST_SELECTED_KEY = "wdt.last_selected_profile"

    def __init__(self, page: "ft.Page") -> None:
        """
        Initialize Flet-based profile manager.

        Args:
            page: Flet page with client_storage access
        """
        self.page = page
        logger.debug("Flet config profile manager initialized")

    def list_profiles(self) -> list[str]:
        """
        List all available profile names from client storage.

        Returns:
            List of profile names (sorted)
        """
        # Get stored list of profile names
        profiles_json = self.page.client_storage.get(self.PROFILE_LIST_KEY)
        if profiles_json:
            try:
                profiles = json.loads(profiles_json)
                return sorted(profiles) if isinstance(profiles, list) else []
            except json.JSONDecodeError:
                logger.warning("Failed to decode profile list, returning empty")
                return []
        return []

    def save_profile(self, name: str, config_adapter: GUIConfigAdapter) -> None:
        """
        Save configuration as named profile in client storage.

        Args:
            name: Profile name
            config_adapter: Configuration adapter to save

        Raises:
            ValueError: If profile name is invalid
        """
        if not name or "/" in name or "\\" in name or "." in name:
            raise ValueError(f"Invalid profile name: {name}")

        # Convert config to JSON string
        config_dict = config_adapter.to_dict()
        config_json = json.dumps(config_dict, indent=2)

        # Store in client storage
        key = f"{self.KEY_PREFIX}{name}"
        self.page.client_storage.set(key, config_json)

        # Update profile list
        profiles = self.list_profiles()
        if name not in profiles:
            profiles.append(name)
            self.page.client_storage.set(self.PROFILE_LIST_KEY, json.dumps(sorted(profiles)))

        logger.info(f"Saved profile to client storage: {name}")

    def load_profile(self, name: str) -> GUIConfigAdapter:
        """
        Load configuration from named profile in client storage.

        Args:
            name: Profile name

        Returns:
            Loaded configuration adapter

        Raises:
            FileNotFoundError: If profile doesn't exist
            ValueError: If profile data is invalid
        """
        key = f"{self.KEY_PREFIX}{name}"

        # Check if key exists
        if not self.page.client_storage.contains_key(key):
            raise FileNotFoundError(f"Profile not found: {name}")

        # Load from client storage
        config_json = self.page.client_storage.get(key)
        if not config_json:
            raise ValueError(f"Profile {name} is empty")

        try:
            config_dict = json.loads(config_json)
            adapter = GUIConfigAdapter()
            adapter.from_dict(config_dict)
            logger.info(f"Loaded profile from client storage: {name}")
            return adapter

        except (json.JSONDecodeError, Exception) as e:
            raise ValueError(f"Invalid profile {name}: {e}") from e

    def delete_profile(self, name: str) -> None:
        """
        Delete a named profile from client storage.

        Args:
            name: Profile name

        Raises:
            FileNotFoundError: If profile doesn't exist
        """
        key = f"{self.KEY_PREFIX}{name}"

        if not self.page.client_storage.contains_key(key):
            raise FileNotFoundError(f"Profile not found: {name}")

        # Remove from storage
        self.page.client_storage.remove(key)

        # Update profile list
        profiles = self.list_profiles()
        if name in profiles:
            profiles.remove(name)
            self.page.client_storage.set(self.PROFILE_LIST_KEY, json.dumps(profiles))

        logger.info(f"Deleted profile from client storage: {name}")

    def profile_exists(self, name: str) -> bool:
        """
        Check if profile exists in client storage.

        Args:
            name: Profile name

        Returns:
            True if profile exists
        """
        key = f"{self.KEY_PREFIX}{name}"
        return self.page.client_storage.contains_key(key)

    def get_or_create_default(self) -> GUIConfigAdapter:
        """
        Get default configuration (always from code, never saved).

        The default config should always come from code (default_config.toml),
        not from saved profiles. This ensures schema changes are properly picked up.

        If an old "default" profile exists in client storage, it will be deleted (migration).

        Returns:
            Fresh default configuration adapter from code
        """
        # Migration: Delete old "default" profile if it exists
        if self.profile_exists("default"):
            logger.info(
                "Deleting old 'default' profile from client storage (migration to code-based defaults)"
            )
            try:
                self.delete_profile("default")
            except Exception as e:
                logger.warning(f"Failed to delete old 'default' profile: {e}")

        # Always return fresh config from code
        return GUIConfigAdapter()

    def set_last_selected_profile(self, profile_name: str) -> None:
        """
        Remember the last selected profile name.

        Args:
            profile_name: Name of the profile to remember
        """
        self.page.client_storage.set(self.LAST_SELECTED_KEY, profile_name)
        logger.debug(f"Saved last selected profile: {profile_name}")

    def get_last_selected_profile(self) -> str:
        """
        Get the last selected profile name.

        Returns:
            Last selected profile name, or "default" if none saved
        """
        last_profile = self.page.client_storage.get(self.LAST_SELECTED_KEY)
        if last_profile and self.profile_exists(last_profile):
            logger.debug(f"Retrieved last selected profile: {last_profile}")
            return last_profile
        else:
            logger.debug("No valid last selected profile, returning 'default'")
            return "default"
