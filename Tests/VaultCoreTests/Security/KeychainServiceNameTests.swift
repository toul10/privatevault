import Testing
@testable import VaultCore

/// Development builds must never share Keychain items with an installed PrivateVault (a restored backup keeps the
/// vault UUID, and the Keychain accounts are `sk:<UUID>` / `bio:<UUID>`).
@Suite("Keychain service namespace")
struct KeychainServiceNameTests {
    @Test func production_app_cli_tools_and_test_runners_use_the_production_service() {
        #expect(KeychainSecretStore.serviceName(forBundleIdentifier: "com.kostastoulis.privatevault") == "com.kostastoulis.privatevault")
        #expect(KeychainSecretStore.serviceName(forBundleIdentifier: nil) == "com.kostastoulis.privatevault")
        #expect(KeychainSecretStore.serviceName(forBundleIdentifier: "com.apple.dt.xctest.tool") == "com.kostastoulis.privatevault")
        #expect(KeychainSecretStore.productionService == "com.kostastoulis.privatevault")
    }

    @Test func development_builds_get_their_own_service() {
        #expect(KeychainSecretStore.serviceName(forBundleIdentifier: "com.kostastoulis.privatevault.dev") == "com.kostastoulis.privatevault.dev")
        #expect(KeychainSecretStore.serviceName(forBundleIdentifier: "com.kostastoulis.privatevault.dev") != KeychainSecretStore.productionService)
    }

    @Test func lookalike_identifiers_do_not_get_a_namespace() {
        #expect(KeychainSecretStore.serviceName(forBundleIdentifier: "com.kostastoulis.privatevaultx") == "com.kostastoulis.privatevault")
        #expect(KeychainSecretStore.serviceName(forBundleIdentifier: "com.kostastoulis.privatevault-dev") == "com.kostastoulis.privatevault")
    }

    @Test func the_process_wide_default_is_the_production_service_outside_a_dev_bundle() {
        // The test runner is not a PrivateVault bundle, so the store's default must be the production service.
        #expect(KeychainSecretStore.service == "com.kostastoulis.privatevault")
    }
}
