import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const response = await fetch(process.env.REACT_APP_API_URL + '/api/data');
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const result = await response.json();
      setData(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    const formData = new FormData(event.target);

    try {
      const response = await fetch(process.env.REACT_APP_API_URL + '/api/submit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: formData.get('name'),
          email: formData.get('email')
        })
      });

      if (response.ok) {
        alert('Data submitted successfully!');
        fetchData(); // Refresh data
      }
    } catch (err) {
      console.error('Submit error:', err);
    }
  };

  if (loading) return <div className="loading">Loading...</div>;
  if (error) return <div className="error">Error: {error}</div>;

  return (
    <div className="App">
      <header className="App-header">
        <h1>DeploymentScanner Demo</h1>
        <p>React Frontend Example</p>
      </header>

      <main className="App-main">
        <section className="data-section">
          <h2>Data from Backend</h2>
          {data.length > 0 ? (
            <ul>
              {data.map((item, index) => (
                <li key={index}>
                  {item.name} - {item.email}
                </li>
              ))}
            </ul>
          ) : (
            <p>No data available</p>
          )}
        </section>

        <section className="form-section">
          <h2>Add New Entry</h2>
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="name">Name:</label>
              <input
                type="text"
                id="name"
                name="name"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="email">Email:</label>
              <input
                type="email"
                id="email"
                name="email"
                required
              />
            </div>

            <button type="submit">Submit</button>
          </form>
        </section>
      </main>

      <footer className="App-footer">
        <p>Environment: {process.env.NODE_ENV}</p>
        <p>API URL: {process.env.REACT_APP_API_URL}</p>
      </footer>
    </div>
  );
}

export default App;
