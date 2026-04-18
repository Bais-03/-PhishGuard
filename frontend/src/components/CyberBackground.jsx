import React, { useEffect, useRef } from 'react'

const CyberBackground = () => {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    
    let animationId
    let nodes = []
    let width = window.innerWidth
    let height = window.innerHeight
    
    // Network nodes data - increased count for better visibility
    const nodeCount = 50
    const connectionDistance = 180
    
    // Initialize nodes with better distribution
    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.3,  // Slightly faster movement
        vy: (Math.random() - 0.5) * 0.3,
        radius: Math.random() * 2.5 + 1.5,  // Slightly larger nodes
      })
    }
    
    const resizeCanvas = () => {
      width = window.innerWidth
      height = window.innerHeight
      canvas.width = width
      canvas.height = height
    }
    
    const draw = () => {
      if (!ctx) return
      
      ctx.clearRect(0, 0, width, height)
      
      // Update node positions
      for (let i = 0; i < nodes.length; i++) {
        const node = nodes[i]
        
        // Move nodes
        node.x += node.vx
        node.y += node.vy
        
        // Bounce off edges with smooth boundary
        if (node.x < 0) {
          node.x = 0
          node.vx *= -1
        }
        if (node.x > width) {
          node.x = width
          node.vx *= -1
        }
        if (node.y < 0) {
          node.y = 0
          node.vy *= -1
        }
        if (node.y > height) {
          node.y = height
          node.vy *= -1
        }
      }
      
      // Draw connections (lines between nearby nodes)
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x
          const dy = nodes[i].y - nodes[j].y
          const distance = Math.sqrt(dx * dx + dy * dy)
          
          if (distance < connectionDistance) {
            // Calculate opacity based on distance - more visible
            const opacity = (1 - distance / connectionDistance) * 0.25
            ctx.beginPath()
            ctx.moveTo(nodes[i].x, nodes[i].y)
            ctx.lineTo(nodes[j].x, nodes[j].y)
            ctx.strokeStyle = `rgba(84, 107, 65, ${opacity})`
            ctx.lineWidth = 0.8
            ctx.stroke()
          }
        }
      }
      
      // Draw nodes (dots)
      for (const node of nodes) {
        ctx.beginPath()
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(84, 107, 65, 0.4)`
        ctx.fill()
        
        // Add subtle glow to nodes
        ctx.beginPath()
        ctx.arc(node.x, node.y, node.radius + 1, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(153, 173, 122, 0.15)`
        ctx.fill()
      }
    }
    
    const animate = () => {
      draw()
      animationId = requestAnimationFrame(animate)
    }
    
    resizeCanvas()
    animate()
    
    window.addEventListener('resize', resizeCanvas)
    
    return () => {
      cancelAnimationFrame(animationId)
      window.removeEventListener('resize', resizeCanvas)
    }
  }, [])
  
  return (
    <canvas
      ref={canvasRef}
      className="fixed top-0 left-0 w-full h-full pointer-events-none"
      style={{ zIndex: 0, opacity: 0.6 }}
    />
  )
}

export default CyberBackground