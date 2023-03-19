import axios, { type AxiosResponse } from 'axios';

export interface AboutInfo {
    version: string;
    timestamp: string;
}

axios.defaults.baseURL = '/api';

const responseBody = <T>(response: AxiosResponse<T>) => response.data;

const request = {
    get: <T>(url: string) => axios.get<T>(url).then(responseBody),
    post: <T>(url: string, body: {}) => axios.post<T>(url, body).then(responseBody),
};

const about = {
    get: () => request.get<AboutInfo>('/about'),
};

const api = {
    about,
};

export default api;