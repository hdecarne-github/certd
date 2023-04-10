function isLocalCA(ca: string|undefined): boolean {
    return ca == 'Local';
}

function isRemoteCA(ca: string|undefined): boolean {
    return ca == 'Remote';
}

function isACMECA(ca: string|undefined): boolean {
    return (ca ?? '').startsWith('ACME:')
}

const defaultKeyTypes: string[] = [
    'ECDSA P-224',
    'ECDSA P-256',
    'ECDSA P-384',
    'ECDSA P-521',
    'ED25519',
    'RSA 2048',
    'RSA 3072',
    'RSA 4092',
];

function getLocalKeyTypes(): string[] {
    return defaultKeyTypes;
}

function getRemoteKeyTypes(): string[] {
    return defaultKeyTypes;
}

const acmeKeyTypes: string[] = [
    'ECDSA P-256',
    'ECDSA P-384',
    'RSA 2048',
    'RSA 3072',
    'RSA 4092',
];

function getACMEKeyTypes(): string[] {
    return acmeKeyTypes;
}

function toValidityDateString(date: Date): string {
    return date.toISOString().substring(0,10);
}

const cert = {
    isLocalCA,
    isRemoteCA,
    isACMECA,
    getLocalKeyTypes,
    getRemoteKeyTypes,
    getACMEKeyTypes,
    toValidityDateString,
};

export default cert;