from App.models.Permissions import Permission


def test_admin_settings_update_permission_value_is_correct():
    assert Permission.ADMIN_SETTINGS_UPDATE.value == "admin.settings.update"
