"""pfsense_get_email_notification_settings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.email_notification_settings import EmailNotificationSettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., EmailNotificationSettings]:
    def pfsense_get_email_notification_settings(
        include_identifying_metadata: bool = False,
    ) -> EmailNotificationSettings:
        """Get pfSense email (SMTP) notification settings: whether
        notifications are enabled, connection options, and
        authentication mechanism. Read-only.

        include_identifying_metadata: if True, includes the SMTP
        username, from/notify addresses, server IP, and password.
        Defaults to False."""
        return client.get_email_notification_settings(include_identifying_metadata=include_identifying_metadata)

    return pfsense_get_email_notification_settings
