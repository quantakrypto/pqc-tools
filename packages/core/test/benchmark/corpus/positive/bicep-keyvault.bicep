resource kvKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  name: 'signing-key'
  properties: {
    kty: 'RSA'
    keySize: 2048
  }
}
