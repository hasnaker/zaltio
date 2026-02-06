'use client';

import React from 'react';

export type NeuralBackgroundIntensity = 'low' | 'medium' | 'high';

export interface NeuralBackgroundProps {
  intensity?: NeuralBackgroundIntensity;
  color?: string;
  animated?: boolean;
  className?: string;
}

/**
 * NeuralBackground Component
 * 
 * An animated neural grid background pattern that creates a synaptic
 * connection effect. Uses SVG patterns for the neural grid.
 * 
 * Requirements: 1.2
 */
export function NeuralBackground({
  intensity = 'medium',
  color = '#00F5D4',
  animated = true,
  className = '',
}: NeuralBackgroundProps) {
  const intensityConfig: Record<NeuralBackgroundIntensity, { opacity: number; gridSize: number; nodeCount: number }> = {
    low: { opacity: 0.1, gridSize: 60, nodeCount: 8 },
    medium: { opacity: 0.2, gridSize: 50, nodeCount: 12 },
    high: { opacity: 0.3, gridSize: 40, nodeCount: 16 },
  };

  const config = intensityConfig[intensity];
  const animationClass = animated ? 'animate-neural-flow' : '';

  // Generate neural nodes for the pattern
  const generateNodes = () => {
    const nodes = [];
    for (let i = 0; i < config.nodeCount; i++) {
      const x = (i % 4) * 25 + 12.5;
      const y = Math.floor(i / 4) * 25 + 12.5;
      nodes.push(
        <circle
          key={`node-${i}`}
          cx={`${x}%`}
          cy={`${y}%`}
          r="2"
          fill={color}
          opacity={config.opacity * 1.5}
        />
      );
    }
    return nodes;
  };

  // Generate connection lines between nodes
  const generateConnections = () => {
    const connections = [];
    const positions = [];
    
    for (let i = 0; i < config.nodeCount; i++) {
      positions.push({
        x: (i % 4) * 25 + 12.5,
        y: Math.floor(i / 4) * 25 + 12.5,
      });
    }

    for (let i = 0; i < positions.length; i++) {
      for (let j = i + 1; j < positions.length; j++) {
        const distance = Math.sqrt(
          Math.pow(positions[j].x - positions[i].x, 2) +
          Math.pow(positions[j].y - positions[i].y, 2)
        );
        
        // Only connect nearby nodes
        if (distance < 40) {
          connections.push(
            <line
              key={`connection-${i}-${j}`}
              x1={`${positions[i].x}%`}
              y1={`${positions[i].y}%`}
              x2={`${positions[j].x}%`}
              y2={`${positions[j].y}%`}
              stroke={color}
              strokeWidth="0.5"
              opacity={config.opacity * 0.5}
            />
          );
        }
      }
    }
    return connections;
  };

  return (
    <div
      className={`absolute inset-0 overflow-hidden ${className}`}
      data-intensity={intensity}
      data-animated={animated}
      aria-hidden="true"
    >
      {/* Base gradient background */}
      <div className="absolute inset-0 bg-gradient-to-br from-nexus-cosmic-black via-nexus-cosmic-deep to-nexus-cosmic-black" />
      
      {/* Neural grid pattern */}
      <svg
        className={`absolute inset-0 w-full h-full ${animationClass}`}
        style={{
          backgroundSize: `${config.gridSize}px ${config.gridSize}px`,
        }}
        preserveAspectRatio="xMidYMid slice"
      >
        <defs>
          {/* Grid pattern */}
          <pattern
            id="neural-grid"
            width={config.gridSize}
            height={config.gridSize}
            patternUnits="userSpaceOnUse"
          >
            <path
              d={`M ${config.gridSize} 0 L 0 0 0 ${config.gridSize}`}
              fill="none"
              stroke={color}
              strokeWidth="0.5"
              opacity={config.opacity * 0.3}
            />
          </pattern>
          
          {/* Radial gradient for glow effect */}
          <radialGradient id="neural-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={color} stopOpacity={config.opacity * 0.4} />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </radialGradient>
        </defs>
        
        {/* Grid background */}
        <rect width="100%" height="100%" fill="url(#neural-grid)" />
        
        {/* Neural connections */}
        <g className={animated ? 'animate-pulse-slow' : ''}>
          {generateConnections()}
        </g>
        
        {/* Neural nodes */}
        <g className={animated ? 'animate-glow-pulse' : ''}>
          {generateNodes()}
        </g>
        
        {/* Central glow effect */}
        <ellipse
          cx="50%"
          cy="50%"
          rx="40%"
          ry="40%"
          fill="url(#neural-glow)"
        />
      </svg>
      
      {/* Overlay gradient for depth */}
      <div 
        className="absolute inset-0 bg-gradient-radial from-transparent via-transparent to-nexus-cosmic-black/50"
        style={{ opacity: 0.6 }}
      />
    </div>
  );
}

export default NeuralBackground;
