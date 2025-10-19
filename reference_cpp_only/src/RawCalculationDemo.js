import React, { useState } from 'react';
import { runPSIInWorker } from './workerAdapter';

const RawCalculationDemo = () => {
  // Static positions from your old App.js
  const bobUnits = [
    { id: 'u1', x: 100, y: 100 },
    { id: 'u2', x: 200, y: 200 },
    { id: 'u3', x: 450, y: 450 },
  ];

  const aliceUnits = [
    { id: 'u1', x: 150, y: 150 },
    { id: 'u2', x: 250, y: 250 },
    { id: 'u3', x: 350, y: 350 },
    { id: 'u4', x: 450, y: 450 },
    { id: 'u5', x: 451, y: 450 },
    { id: 'u6', x: 452, y: 450 },
    { id: 'u7', x: 453, y: 450 },
    { id: 'u8', x: 454, y: 450 },
    { id: 'u9', x: 455, y: 450 },
  ];

  const [bobValues, setBobValues] = useState([]);
  const [aliceValues, setAliceValues] = useState([]);
  const [results, setResults] = useState([]);
  const [calculationTime, setCalculationTime] = useState(null);
  const [isCalculating, setIsCalculating] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);
  const [backendName, setBackendName] = useState(null);
  const [performanceStats, setPerformanceStats] = useState(null);

  const runPSIProtocol = () => {
    console.log('Starting PSI Protocol via C++ backend - Raw Calculation Demo');
    setIsCalculating(true);
    setErrorMessage(null);
    setBackendName(null);
    setPerformanceStats(null);
    setCalculationTime(null);

    runPSIInWorker(bobUnits, aliceUnits, {
      onStart: () => {
        setIsCalculating(true);
      },
      onSuccess: (data) => {
        setBobValues(data.bobValues || []);
        setAliceValues(data.aliceValues || []);
        setResults(data.results || []);
        if (data.backend) {
          setBackendName(data.backend);
        }
        if (data.performance) {
          setPerformanceStats(data.performance);
          if (typeof data.performance.totalTime === 'number') {
            setCalculationTime(data.performance.totalTime);
          }
        }
        setIsCalculating(false);
      },
      onError: (error) => {
        console.error('C++ PSI request failed', error);
        setErrorMessage(error?.message || 'PSI C++ server request failed.');
        setIsCalculating(false);
      }
    });
  };

  // Helper function to format encrypted values
  const formatEncryptedValue = (value) => {
    const shorten = (text) => {
      const valueStr = String(text ?? '');
      return valueStr.length <= 24 ? valueStr : `${valueStr.slice(0, 12)}…${valueStr.slice(-6)}`;
    };
    if (typeof value === 'string') {
      // For strings, show first few and last few characters
      if (value.length > 20) {
        return `${value.substring(0, 10)}...${value.substring(value.length - 5)}`;
      }
      return value;
    } else if (value && typeof value === 'object') {
      const parts = [];
      if (value.unit) {
        parts.push(`unit: ${value.unit}`);
      }
      if (value.ciphertext) {
        parts.push(`ciphertext: ${shorten(value.ciphertext)}`);
      }
      if (value.nonce) {
        parts.push(`nonce: ${shorten(value.nonce)}`);
      }
      if (value.blindedPoint) {
        parts.push(`blinded: ${shorten(value.blindedPoint)}`);
      }
      if (value.transformedPoint) {
        parts.push(`transformed: ${shorten(value.transformedPoint)}`);
      }
      return parts.length > 0 ? parts.join(' | ') : 'Encrypted payload';
    } else {
      return String(value ?? '');
    }
  };

  return (
    <div className="raw-calculation-container" style={{ 
      padding: '20px', 
      maxWidth: '800px', 
      margin: '0 auto',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    }}>
      <h1 style={{ color: '#2c3e50', borderBottom: '2px solid #eee', paddingBottom: '10px' }}>
        PSI Calculation Demo (C++ Backend)
      </h1>
      
      <p style={{ fontSize: '16px', lineHeight: '1.5', color: '#555' }}>
        Each run calls the C++ <code>psi_server</code> over HTTP (default <code>http://localhost:8080/psi</code>). If the backend is unavailable, the UI will surface an error and no PSI work will be performed locally.
      </p>
      
      <div style={{ marginBottom: '30px', textAlign: 'center' }}>
        <button 
          onClick={runPSIProtocol} 
          disabled={isCalculating}
          style={{ 
            padding: '12px 24px', 
            backgroundColor: isCalculating ? '#95a5a6' : '#3498db', 
            color: 'white', 
            border: 'none', 
            borderRadius: '4px',
            cursor: isCalculating ? 'not-allowed' : 'pointer',
            fontSize: '16px',
            fontWeight: 'bold',
            transition: 'background-color 0.3s'
          }}
        >
          {isCalculating ? 'Calculating...' : 'Run PSI Protocol'}
        </button>
        
        {calculationTime != null && (
          <p style={{ marginTop: '10px', color: '#27ae60', fontWeight: 'bold' }}>
            C++ server reported total processing time: {calculationTime.toFixed(2)} ms
          </p>
        )}
        {backendName && !isCalculating && !errorMessage && (
          <p style={{ marginTop: '6px', color: '#2c3e50' }}>
            Response served by: <strong>{backendName}</strong>
          </p>
        )}
        {errorMessage && (
          <p style={{ marginTop: '10px', color: '#c0392b', fontWeight: 'bold' }}>
            {errorMessage}
          </p>
        )}
      </div>

      {performanceStats && !errorMessage && (
        <div style={{
          marginTop: '30px',
          backgroundColor: '#eef2f7',
          padding: '16px',
          borderRadius: '6px',
          border: '1px solid #d6e2f3'
        }}>
          <h3 style={{ marginTop: 0, color: '#2c3e50' }}>Server Timing Breakdown (ms)</h3>
          <ul style={{ listStyleType: 'none', padding: 0, margin: 0, color: '#34495e' }}>
            <li>Total: {performanceStats.totalTime?.toFixed?.(2) ?? 'n/a'}</li>
            <li>Bob setup: {performanceStats.bobSetupTime?.toFixed?.(2) ?? 'n/a'}</li>
            <li>Key exchange (Alice setup + Bob response): {performanceStats.keyExchangeTime?.toFixed?.(2) ?? 'n/a'}</li>
            <li>Alice finalise: {performanceStats.intersectionTime?.toFixed?.(2) ?? 'n/a'}</li>
            <li>Successful decryptions: {performanceStats.successfulDecryptions ?? 'n/a'}</li>
            <li>Inverse operations: {performanceStats.inverseOperations ?? 'n/a'}</li>
            <li>Decrypt operations: {performanceStats.decryptOperations ?? 'n/a'}</li>
          </ul>
        </div>
      )}
      
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: '1fr 1fr', 
        gap: '30px',
        backgroundColor: '#f9f9f9',
        padding: '20px',
        borderRadius: '8px'
      }}>
        <div>
          <h2 style={{ color: '#2980b9', borderBottom: '1px solid #ddd', paddingBottom: '8px' }}>
            Bob's Units
          </h2>
          <ul style={{ listStyleType: 'none', padding: 0 }}>
            {bobUnits.map(unit => (
              <li key={unit.id} style={{ 
                padding: '8px 0', 
                borderBottom: '1px solid #eee',
                display: 'flex',
                justifyContent: 'space-between'
              }}>
                <span style={{ fontWeight: 'bold', color: '#34495e' }}>{unit.id}:</span>
                <span>({unit.x}, {unit.y})</span>
              </li>
            ))}
          </ul>
          
          <h3 style={{ color: '#2980b9', marginTop: '20px' }}>Encrypted Values</h3>
          {bobValues.length > 0 ? (
            <div style={{ 
              backgroundColor: '#eef2f7', 
              padding: '10px', 
              borderRadius: '4px',
              maxHeight: '200px',
              overflowY: 'auto'
            }}>
              <p style={{ margin: '0 0 10px 0', fontStyle: 'italic', color: '#7f8c8d' }}>
                {bobValues.length} values encrypted
              </p>
              {bobValues.slice(0, 5).map((value, index) => (
                <div key={index} style={{ 
                  padding: '8px', 
                  backgroundColor: '#fff', 
                  marginBottom: '5px',
                  borderRadius: '4px',
                  boxShadow: '0 1px 2px rgba(0,0,0,0.05)'
                }}>
                  {formatEncryptedValue(value)}
                </div>
              ))}
              {bobValues.length > 5 && (
                <p style={{ textAlign: 'center', color: '#7f8c8d', margin: '10px 0 0 0' }}>
                  ...and {bobValues.length - 5} more
                </p>
              )}
            </div>
          ) : (
            <p style={{ color: '#7f8c8d', fontStyle: 'italic' }}>
              No encrypted values yet. Click "Run PSI Protocol".
            </p>
          )}
        </div>
        
        <div>
          <h2 style={{ color: '#27ae60', borderBottom: '1px solid #ddd', paddingBottom: '8px' }}>
            Alice's Units
          </h2>
          <ul style={{ listStyleType: 'none', padding: 0 }}>
            {aliceUnits.map(unit => (
              <li key={unit.id} style={{ 
                padding: '8px 0', 
                borderBottom: '1px solid #eee',
                display: 'flex',
                justifyContent: 'space-between'
              }}>
                <span style={{ fontWeight: 'bold', color: '#34495e' }}>{unit.id}:</span>
                <span>({unit.x}, {unit.y})</span>
              </li>
            ))}
          </ul>
          
          <h3 style={{ color: '#27ae60', marginTop: '20px' }}>Encrypted Values</h3>
          {aliceValues.length > 0 ? (
            <div style={{ 
              backgroundColor: '#eef7ee', 
              padding: '10px', 
              borderRadius: '4px',
              maxHeight: '200px',
              overflowY: 'auto'
            }}>
              <p style={{ margin: '0 0 10px 0', fontStyle: 'italic', color: '#7f8c8d' }}>
                {aliceValues.length} values encrypted
              </p>
              {aliceValues.slice(0, 5).map((value, index) => (
                <div key={index} style={{ 
                  padding: '8px', 
                  backgroundColor: '#fff', 
                  marginBottom: '5px',
                  borderRadius: '4px',
                  boxShadow: '0 1px 2px rgba(0,0,0,0.05)'
                }}>
                  {formatEncryptedValue(value)}
                </div>
              ))}
              {aliceValues.length > 5 && (
                <p style={{ textAlign: 'center', color: '#7f8c8d', margin: '10px 0 0 0' }}>
                  ...and {aliceValues.length - 5} more
                </p>
              )}
            </div>
          ) : (
            <p style={{ color: '#7f8c8d', fontStyle: 'italic' }}>
              No encrypted values yet. Click "Run PSI Protocol".
            </p>
          )}
        </div>
      </div>
      
      <div style={{ 
        marginTop: '30px', 
        backgroundColor: '#f0f7fc', 
        padding: '20px', 
        borderRadius: '8px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
      }}>
        <h2 style={{ color: '#e74c3c', borderBottom: '1px solid #ddd', paddingBottom: '8px' }}>
          PSI Results
        </h2>
        {results.length > 0 ? (
          <div>
            <p style={{ fontSize: '16px', color: '#2c3e50' }}>
              Found <strong>{results.length}</strong> intersections:
            </p>
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))',
              gap: '10px',
              marginTop: '15px'
            }}>
              {results.map((result, index) => (
                <div key={index} style={{ 
                  padding: '10px', 
                  backgroundColor: '#fff', 
                  borderRadius: '4px',
                  border: '1px solid #e74c3c',
                  textAlign: 'center',
                  fontWeight: 'bold',
                  color: '#e74c3c'
                }}>
                  {result.unit}
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '20px 0' }}>
            {isCalculating ? (
              <p style={{ color: '#7f8c8d' }}>Calculating intersections...</p>
            ) : (
              <p style={{ color: '#7f8c8d' }}>No results yet. Click "Run PSI Protocol".</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default RawCalculationDemo; 
