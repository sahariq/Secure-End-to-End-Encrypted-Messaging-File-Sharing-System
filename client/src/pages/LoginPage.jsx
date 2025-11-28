import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { 
  loadKeyPair, 
  generateECCKeyPair, 
  saveKeyPair, 
  exportPublicKeyAsJWKString,
  loadSigningKeyPair,
  generateSigningKeyPair,
  saveSigningKeyPair
} from '../crypto/keyManager';
import './LoginPage.css';

// Use direct axios for login (no token needed yet)
const API_URL = 'http://localhost:5000/api';

function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [keyStatus, setKeyStatus] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await axios.post(`${API_URL}/auth/login`, {
        username,
        password
      });

      if (response.data && response.data.token) {
        // Store JWT token in localStorage
        // TODO (STEP 3+): Consider moving to httpOnly cookies or secure storage
        localStorage.setItem('authToken', response.data.token);
        localStorage.setItem('userId', response.data.userId);
        localStorage.setItem('username', response.data.username);
        
        // Check for existing key pair or generate new one
        setKeyStatus('Checking for device keys...');
        
        try {
          const keyPair = await loadKeyPair();
          const signingKeyPair = await loadSigningKeyPair();
          
          if (keyPair && signingKeyPair) {
            // Keys found, load successful
            setKeyStatus('Keys loaded successfully.');
            console.log('Loaded existing ECC key pair');
            
            // Export and log public key
            const publicKeyJWK = await exportPublicKeyAsJWKString();
            console.log('Public Key (JWK):', publicKeyJWK);
            
            // Redirect after brief delay
            setTimeout(() => {
              navigate('/chat');
            }, 500);
          } else {
            // No keys found, generate new pairs
            setKeyStatus('No keys found, generating fresh ones...');
            
            // Generate ECDH key pair for key exchange
            const { privateKey, publicKey } = await generateECCKeyPair();
            await saveKeyPair(privateKey, publicKey);
            
            // Generate ECDSA key pair for signing
            const signingKeys = await generateSigningKeyPair();
            await saveSigningKeyPair(signingKeys.privateKey, signingKeys.publicKey);
            
            const publicKeyJWK = await exportPublicKeyAsJWKString();
            console.log('Generated new ECC key pairs (ECDH + ECDSA)');
            console.log('Public Key (JWK):', publicKeyJWK);
            
            setKeyStatus('Keys generated successfully!');
            
            // Redirect after brief delay
            setTimeout(() => {
              navigate('/chat');
            }, 1000);
          }
        } catch (keyError) {
          console.error('Error handling keys:', keyError);
          setKeyStatus('Login successful, but key operation failed. You can still use the app.');
          // Still redirect even if key operation fails
          setTimeout(() => {
            navigate('/chat');
          }, 1500);
        }
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-container">
        <h1>Login</h1>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              placeholder="Enter username"
            />
          </div>
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              placeholder="Enter password"
            />
          </div>
          {error && <div className="error-message">{error}</div>}
          {keyStatus && (
            <div className={keyStatus.includes('failed') ? 'error-message' : 'success-message'}>
              {keyStatus}
            </div>
          )}
          <button type="submit" disabled={loading || keyStatus.includes('Checking') || keyStatus.includes('generating')}>
            {loading ? 'Logging in...' : keyStatus.includes('Checking') || keyStatus.includes('generating') ? 'Setting up keys...' : 'Login'}
          </button>
        </form>
        <p className="register-link">
          Don't have an account? <Link to="/register">Register here</Link>
        </p>
      </div>
    </div>
  );
}

export default LoginPage;

