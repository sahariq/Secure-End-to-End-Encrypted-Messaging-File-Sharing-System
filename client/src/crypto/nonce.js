/**
 * Generate a random nonce string
 * 
 * @returns {string} Base64 encoded random bytes
 */
export const generateNonce = () => {
    const array = new Uint8Array(16);
    window.crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array));
};
