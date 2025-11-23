import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { generateECCKeyPair, saveKeyPair, exportPublicKeyAsJWKString } from '../crypto/keyManager';
import './RegisterPage.css';

// Use direct axios for registration (no token needed)
const API_URL = 'http://localhost:5000/api';

function RegisterPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [keyGenStatus, setKeyGenStatus] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await axios.post(`${API_URL}/auth/register`, {
        username,
        password
      });

      if (response.data) {
        // After successful registration, generate ECC key pair
        setKeyGenStatus('Generating secure device keys...');
        
        try {
          // Generate ECC P-256 key pair
          const { privateKey, publicKey } = await generateECCKeyPair();
          
          // Store keys securely in IndexedDB
          await saveKeyPair(privateKey, publicKey);
          
          // Export public key as JWK string (for future key exchange)
          const publicKeyJWK = await exportPublicKeyAsJWKString();
          
          // Log the exported public key (will be sent to server in STEP 4)
          console.log('Generated ECC key pair successfully');
          console.log('Public Key (JWK):', publicKeyJWK);
          
          setKeyGenStatus('Keys generated successfully!');
          
          // Small delay to show success message
          setTimeout(() => {
            // Redirect to login page after successful registration and key generation
            navigate('/login');
          }, 1000);
        } catch (keyError) {
          console.error('Error generating keys:', keyError);
          setKeyGenStatus('Registration successful, but key generation failed. You can generate keys on login.');
          // Still redirect to login even if key generation fails
          setTimeout(() => {
            navigate('/login');
          }, 2000);
        }
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="register-page">
      <div className="register-container">
        <h1>Register</h1>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              minLength={3}
              maxLength={30}
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
          {keyGenStatus && (
            <div className={keyGenStatus.includes('failed') ? 'error-message' : 'success-message'}>
              {keyGenStatus}
            </div>
          )}
          <button type="submit" disabled={loading || keyGenStatus.includes('Generating')}>
            {loading ? 'Registering...' : keyGenStatus.includes('Generating') ? 'Generating keys...' : 'Register'}
          </button>
        </form>
        <p className="login-link">
          Already have an account? <Link to="/login">Login here</Link>
        </p>
      </div>
    </div>
  );
}

export default RegisterPage;

