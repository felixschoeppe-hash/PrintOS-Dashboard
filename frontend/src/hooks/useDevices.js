import { useState, useEffect } from 'react';
import axios from 'axios';

const API_URL = 'https://printos-backend.onrender.com/api';

export const useDevices = () => {
  const [devices, setDevices] = useState([]);
  const [deviceNames, setDeviceNames] = useState({ 'all': 'Alle Pressen' });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDevices();
  }, []);

  const fetchDevices = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        setLoading(false);
        return;
      }

      const response = await axios.get(API_URL + '/settings/devices', {
        headers: { Authorization: 'Bearer ' + token }
      });

// Handle different response formats
let deviceList = [];
if (response.data) {
  if (Array.isArray(response.data)) {
    deviceList = response.data;
  } else if (Array.isArray(response.data.device_list)) {
    // ← FIX: API returns "device_list" not "devices"!
    deviceList = response.data.device_list;
  } else if (Array.isArray(response.data.devices)) {
    deviceList = response.data.devices;
  } else if (response.data.devices && typeof response.data.devices === 'object') {
    deviceList = Object.values(response.data.devices);
  }
}

setDevices(deviceList);

// Create deviceNames object
const names = { 'all': 'Alle Pressen' };
deviceList.forEach(device => {
  if (device && device.id) {
    names[device.id] = device.name || device.id;
  }
});

setDeviceNames(names);
    } catch (error) {
      console.error('Error loading devices:', error);
      // Set empty array on error
      setDevices([]);
      setDeviceNames({ 'all': 'Alle Pressen' });
    } finally {
      setLoading(false);
    }
  };

  return { devices, deviceNames, loading, refetch: fetchDevices };
};
