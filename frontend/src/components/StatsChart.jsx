import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
  Filler
} from 'chart.js';
import { Bar, Pie, Line } from 'react-chartjs-2';

// Register ChartJS modules
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
  Filler
);

export const StatsChart = ({ type = 'bar', data = {} }) => {
  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          color: '#94A3B8', // Slate 400
          font: { family: 'Inter', size: 11 }
        }
      },
      tooltip: {
        padding: 10,
        backgroundColor: '#160A29',
        titleFont: { family: 'Outfit', size: 13 },
        bodyFont: { family: 'Inter', size: 12 },
        borderWidth: 1,
        borderColor: '#2B154E'
      }
    },
    scales: type !== 'pie' ? {
      x: {
        grid: { color: 'rgba(255,255,255,0.03)' },
        ticks: { color: '#64748B', font: { size: 10 } }
      },
      y: {
        grid: { color: 'rgba(255,255,255,0.03)' },
        ticks: { color: '#64748B', font: { size: 10 } }
      }
    } : {}
  };

  if (type === 'pie') {
    const pieData = {
      labels: Object.keys(data),
      datasets: [
        {
          label: 'Scan Count',
          data: Object.values(data),
          backgroundColor: [
            'rgba(16, 185, 129, 0.2)', // Safe
            'rgba(245, 158, 11, 0.2)',  // Suspicious
            'rgba(239, 68, 68, 0.2)'    // Dangerous
          ],
          borderColor: [
            '#10B981',
            '#F59E0B',
            '#EF4444'
          ],
          borderWidth: 1.5,
        }
      ]
    };
    return <div className="h-64"><Pie data={pieData} options={chartOptions} /></div>;
  }

  if (type === 'bar') {
    const barData = {
      labels: Object.keys(data).map(k => k.toUpperCase()),
      datasets: [
        {
          label: 'Scans Initiated',
          data: Object.values(data),
          backgroundColor: 'rgba(107, 33, 228, 0.25)', // Vibrant Purple
          borderColor: '#6B21E4',
          borderWidth: 1.5,
          borderRadius: 6,
        }
      ]
    };
    return <div className="h-64"><Bar data={barData} options={chartOptions} /></div>;
  }

  if (type === 'line') {
    const lineData = {
      labels: Object.keys(data),
      datasets: [
        {
          fill: true,
          label: 'Total Incidents',
          data: Object.values(data),
          borderColor: '#B289FA', // Accent Light Purple
          backgroundColor: 'rgba(178, 137, 250, 0.1)',
          borderWidth: 2,
          pointBackgroundColor: '#B289FA',
          tension: 0.3
        }
      ]
    };
    return <div className="h-64"><Line data={lineData} options={chartOptions} /></div>;
  }

  return null;
};
