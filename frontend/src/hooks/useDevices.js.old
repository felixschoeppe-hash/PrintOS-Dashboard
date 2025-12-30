import { useState, useEffect } from 'react';
import axios from 'axios';

const API_URL = 'https://printos-backend.onrender.com/api';

export const useDevices = () => {
  const [devices, setDevices] = useState([]);
  const [deviceNames, setDeviceNames] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDevices();
  }, []);

  const fetchDevices = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(API_URL + '/settings/devices', {
        headers: { Authorization: 'Bearer ' + token }
      });

      setDevices(response.data.devices || []);
      
      // Erstelle deviceNames Object: { "47200413": "Custom Name", ... }
      const names = {};
      if (response.data.devices) {
        response.data.devices.forEach(device => {
          names[device.device_id] = device.name || device.device_id;
        });
      }
      names['all'] = 'Alle Pressen';
      
      setDeviceNames(names);
    } catch (error) {
      console.error('Error loading devices:', error);
      // Fallback zu leeren Namen
      setDeviceNames({ 'all': 'Alle Pressen' });
    } finally {
      setLoading(false);
    }
  };

  return { devices, deviceNames, loading, refetch: fetchDevices };
};
