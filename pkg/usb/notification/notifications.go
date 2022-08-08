package notification

const (
	SyncWillStart   = "com.apple.itunes-mobdev.syncWillStart"
	SyncDidStart    = "com.apple.itunes-mobdev.syncDidStart"
	SyncDidFinish   = "com.apple.itunes-mobdev.syncDidFinish"
	SyncLockRequest = "com.apple.itunes-mobdev.syncLockRequest"
)

const (
	SyncCancelRequest            = "com.apple.itunes-client.syncCancelRequest"
	SyncSuspendRequest           = "com.apple.itunes-client.syncSuspendRequest"
	SyncResumeRequest            = "com.apple.itunes-client.syncResumeRequest"
	PhoneNumberChanged           = "com.apple.mobile.lockdown.phone_number_changed"
	DeviceNameChanged            = "com.apple.mobile.lockdown.device_name_changed"
	TimezoneChanged              = "com.apple.mobile.lockdown.timezone_changed"
	TrustedHostAttached          = "com.apple.mobile.lockdown.trusted_host_attached"
	HostDetached                 = "com.apple.mobile.lockdown.host_detached"
	HostAttached                 = "com.apple.mobile.lockdown.host_attached"
	RegistrationFailed           = "com.apple.mobile.lockdown.registration_failed"
	ActivationState              = "com.apple.mobile.lockdown.activation_state"
	BrickState                   = "com.apple.mobile.lockdown.brick_state"
	DiskUageChanged              = "com.apple.mobile.lockdown.disk_usage_changed"
	DataSyncDomainChanged        = "com.apple.mobile.data_sync.domain_changed"
	BackupDomainChanged          = "com.apple.mobile.backup.domain_changed"
	ApplicationInstalled         = "com.apple.mobile.application_installed"
	ApplicationUninstalled       = "com.apple.mobile.application_uninstalled"
	DeveloperImageMounter        = "com.apple.mobile.developer_image_mounted"
	AttemptActivation            = "com.apple.springboard.attemptactivation"
	ITDBPrepNoficationDidEnd     = "com.apple.itdbprep.notification.didEnd"
	LanguageChanged              = "com.apple.language.changed"
	AddressBookPreferenceChanged = "com.apple.AddressBook.PreferenceChanged"
)
