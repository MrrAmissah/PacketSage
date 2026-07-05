import React, { useState, useRef, useEffect } from 'react';
import { Info } from 'lucide-react';

interface InfoPopoverProps {
  content: string;
  align?: 'left' | 'right' | 'center';
  position?: 'top' | 'bottom';
  className?: string;
  iconSize?: number;
}

export default function InfoPopover({
  content,
  align = 'right',
  position = 'bottom',
  className = '',
  iconSize = 13
}: InfoPopoverProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [coords, setCoords] = useState<{ top: number; left: number } | null>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const updatePosition = () => {
    if (!buttonRef.current) return;

    const triggerRect = buttonRef.current.getBoundingClientRect();
    
    // We measure the popover if mounted, otherwise fallback to standard sizes
    const popoverWidth = popoverRef.current ? popoverRef.current.offsetWidth : 288;
    const popoverHeight = popoverRef.current ? popoverRef.current.offsetHeight : 120;
    const margin = 12;

    // 1. Calculate left position based on alignment
    let left = 0;
    if (align === 'left') {
      left = triggerRect.left;
    } else if (align === 'center') {
      left = triggerRect.left + (triggerRect.width / 2) - (popoverWidth / 2);
    } else {
      left = triggerRect.right - popoverWidth;
    }

    // Clamp left to viewport boundaries
    const maxLeft = window.innerWidth - popoverWidth - margin;
    left = Math.max(margin, Math.min(maxLeft, left));

    // 2. Calculate top position based on orientation
    let top = 0;
    if (position === 'top') {
      top = triggerRect.top - popoverHeight - 8;
      // If cuts off on top, fallback to bottom
      if (top < margin) {
        top = triggerRect.bottom + 8;
      }
    } else {
      top = triggerRect.bottom + 8;
      // If cuts off on bottom, fallback to top
      if (top + popoverHeight > window.innerHeight - margin) {
        top = triggerRect.top - popoverHeight - 8;
      }
    }

    setCoords({ top, left });
  };

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        // Also check if clicked inside the fixed popover itself
        if (popoverRef.current && popoverRef.current.contains(event.target as Node)) {
          return;
        }
        setIsOpen(false);
      }
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setIsOpen(false);
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleKeyDown);
      
      // Update layout immediately
      updatePosition();
      
      // Keep popover attached on scroll or viewport changes
      window.addEventListener('scroll', updatePosition, true);
      window.addEventListener('resize', updatePosition);
      
      // Double check layout sizing after a frame
      const frameId = requestAnimationFrame(updatePosition);
      
      return () => {
        document.removeEventListener('mousedown', handleClickOutside);
        document.removeEventListener('keydown', handleKeyDown);
        window.removeEventListener('scroll', updatePosition, true);
        window.removeEventListener('resize', updatePosition);
        cancelAnimationFrame(frameId);
      };
    } else {
      setCoords(null);
    }
  }, [isOpen]);

  // Recalculate if content changes while open
  useEffect(() => {
    if (isOpen) {
      updatePosition();
    }
  }, [content]);

  return (
    <div id="info-popover-wrapper" className={`inline-block relative leading-none ${className}`} ref={containerRef}>
      <button
        ref={buttonRef}
        type="button"
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setIsOpen(!isOpen);
        }}
        className="text-text-muted hover:text-text-primary hover:bg-surface-muted p-0.5 rounded transition-all cursor-pointer inline-flex items-center justify-center"
        title="More information"
        aria-label="More information"
      >
        <Info size={iconSize} />
      </button>

      {isOpen && (
        <div 
          ref={popoverRef}
          id="info-popover-content"
          style={{
            position: 'fixed',
            top: coords ? `${coords.top}px` : '0px',
            left: coords ? `${coords.left}px` : '0px',
            opacity: coords ? 1 : 0,
            pointerEvents: coords ? 'auto' : 'none',
          }}
          className="z-50 w-72 sm:w-80 p-3 bg-surface border border-border-strong rounded-xl text-[11px] text-text-muted leading-relaxed shadow-lg transition-opacity duration-150 font-normal whitespace-normal text-left"
        >
          {content}
        </div>
      )}
    </div>
  );
}
