import axios, { type AxiosResponse } from 'axios';

export class AboutInfo {
	version: string = '';
	timestamp: string = '';
}

const responseBody = <T>(response: AxiosResponse<T>) => response.data;

const request = {
	get: <T>(url: string) => axios.get<T>(url).then(responseBody),
	put: <T>(url: string, body: object) => axios.put<T>(url, body).then(responseBody)
};

const about = {
	get: (basePath: string) => request.get<AboutInfo>(`${basePath}/api/about`)
};

export class StoreEntries {
	entries: StoreEntry[] = [];
}

export class StoreEntry {
	name: string = "";
	dn: string = "";
	ca: boolean = false;
	key: boolean = false;
	crt: boolean = false;
	csr: boolean = false;
	crl: boolean = false;
	valid_from: Date = new Date(0);
	valid_to: Date = new Date(0);
}

const storeEntries = {
	get: (basePath: string) => request.get<StoreEntries>(`${basePath}/api/store/entries`)
};

export class StoreEntryDetails extends StoreEntry {
	crt_details: StoreEntryCRTDetails = new StoreEntryCRTDetails();
}

export class StoreEntryCRTDetails {
	version: number = -1;
	serial: string = '';
	key_type: string = '';
	issuer: string = '';
	sig_alg: string = '';
	extensions: string[2][] = [];
}

const storeEntryDetails = {
	get: (basePath: string, name: string) => request.get<StoreEntryDetails>(`${basePath}/api/store/entry/details/${name}`)
};

export class StoreCAs {
	cas: StoreCA[] = [];
}

export class StoreCA {
	name: string = '';
}

const storeCAs = {
	get: (basePath: string) => request.get<StoreCAs>(`${basePath}/api/store/cas`)
};

export class StoreLocalIssuers {
	issuers: StoreLocalIssuer[] = [];
}

export class StoreLocalIssuer {
	name: string = '';
}

const storeLocalIssuers = {
	get: (basePath: string) => request.get<StoreLocalIssuers>(`${basePath}/api/store/local/issuers`)
};

export class StoreGenerate {
	name: string = '';
	ca: string = '';
}

export class StoreLocalGenerate extends StoreGenerate {
	dn: string = '';
	key_type: string = '';
	issuer: string = '';
	valid_from: Date = new Date(0);
	valid_to: Date = new Date(0);
	key_usage: KeyUsageExtensionSpec = new KeyUsageExtensionSpec();
	ext_key_usage: ExtKeyUsageExtensionSpec = new ExtKeyUsageExtensionSpec();
	basic_constraint: BasicConstraintExtensionSpec = new BasicConstraintExtensionSpec();
}

export class ExtensionSpec {
	enabled: boolean = false;
}

export class KeyUsageExtensionSpec extends ExtensionSpec {
	digital_signature: boolean = false;
	content_commitment: boolean = false;
	key_encipherment: boolean = false;
	data_encipherment: boolean = false;
	key_agreement: boolean = false;
	cert_sign: boolean = false;
	crl_sign: boolean = false;
	encipher_only: boolean = false;
	decipher_only: boolean = false;
}

export class ExtKeyUsageExtensionSpec extends ExtensionSpec {
	any: boolean = false;
	server_auth: boolean = false;
	client_auth: boolean = false;
	code_signing: boolean = false;
	email_protection: boolean = false;
	ipsec_end_system: boolean = false;
	ipsec_tunnel: boolean = false;
	ipsec_user: boolean = false;
	time_stamping: boolean = false;
	ocsp_signing: boolean = false;
	microsoft_server_gated_crypto: boolean = false;
	netscape_server_gated_crypto: boolean = false;
	microsoft_commercial_code_signing: boolean = false;
	microsoft_kernel_code_signing: boolean = false;
}

export class BasicConstraintExtensionSpec extends ExtensionSpec {
	ca: boolean = false;
	path_len: number = -1;
}

const storeLocalGenerate = {
	put: (basePath: string, body: StoreLocalGenerate) => request.put<void>(`${basePath}/api/store/local/generate`, body)
};

export class StoreRemoteGenerate extends StoreGenerate {
	dn: string = '';
	key_type: string = '';
}

const storeRemoteGenerate = {
	put: (basePath: string, body: StoreRemoteGenerate) => request.put<void>(`${basePath}/api/store/remote/generate`, body)
};

export class StoreACMEGenerate extends StoreGenerate {
	domains: string[] = [];
	key_type: string = '';
}

const storeACMEGenerate = {
	put: (basePath: string, body: StoreRemoteGenerate) => request.put<void>(`${basePath}/api/store/acme/generate`, body)
};

const api = {
	about,
	storeEntries,
	storeEntryDetails,
	storeCAs,
	storeLocalIssuers,
	storeLocalGenerate,
	storeRemoteGenerate,
	storeACMEGenerate,
};

export default api;
