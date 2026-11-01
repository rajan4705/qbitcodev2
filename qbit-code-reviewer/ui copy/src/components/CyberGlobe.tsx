import React, { useEffect, useRef } from 'react';

export const CyberGlobe: React.FC<{ size?: number }> = ({ size = 160 }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animId: number;
    let angle = 0;

    // Generate sphere points (latitude / longitude grid)
    const points: [number, number, number][] = [];
    const radius = size * 0.42;
    const latCount = 18;
    const lonCount = 26;

    for (let i = 0; i < latCount; i++) {
      const theta = (i * Math.PI) / (latCount - 1) - Math.PI / 2;
      for (let j = 0; j < lonCount; j++) {
        const phi = (j * 2 * Math.PI) / lonCount;
        const x = radius * Math.cos(theta) * Math.cos(phi);
        const y = radius * Math.sin(theta);
        const z = radius * Math.cos(theta) * Math.sin(phi);
        points.push([x, y, z]);
      }
    }

    const render = () => {
      ctx.clearRect(0, 0, size, size);
      const cx = size / 2;
      const cy = size / 2;

      angle += 0.012;
      const cosA = Math.cos(angle);
      const sinA = Math.sin(angle);
      const tilt = 0.25;
      const cosT = Math.cos(tilt);
      const sinT = Math.sin(tilt);

      // Outer glowing ring
      ctx.beginPath();
      ctx.arc(cx, cy, radius + 4, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.2)';
      ctx.lineWidth = 1;
      ctx.stroke();

      for (let i = 0; i < points.length; i++) {
        const [x0, y0, z0] = points[i];

        // Y-axis rotation
        const x1 = x0 * cosA - z0 * sinA;
        const z1 = z0 * cosA + x0 * sinA;

        // X-axis tilt
        const y2 = y0 * cosT - z1 * sinT;
        const z2 = z1 * cosT + y0 * sinT;

        // Perspective projection
        const scale = 240 / (240 + z2);
        const px = cx + x1 * scale;
        const py = cy + y2 * scale;

        // Depth cueing & electric blue coloring
        const alpha = Math.max(0.1, (z2 + radius) / (2 * radius));
        const dotRadius = Math.max(0.7, scale * 1.4);

        ctx.beginPath();
        ctx.arc(px, py, dotRadius, 0, Math.PI * 2);
        if (z2 > 0) {
          // Front hemisphere glows brightly
          ctx.fillStyle = `rgba(0, 240, 255, ${alpha.toFixed(2)})`;
          ctx.shadowColor = '#00f0ff';
          ctx.shadowBlur = 4;
        } else {
          // Back hemisphere is dimmer blue
          ctx.fillStyle = `rgba(0, 112, 243, ${(alpha * 0.4).toFixed(2)})`;
          ctx.shadowBlur = 0;
        }
        ctx.fill();
      }

      animId = requestAnimationFrame(render);
    };

    render();

    return () => cancelAnimationFrame(animId);
  }, [size]);

  return (
    <div style={{ position: 'relative', width: size, height: size, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <canvas ref={canvasRef} width={size} height={size} style={{ display: 'block' }} />
    </div>
  );
};
