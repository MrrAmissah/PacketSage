import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
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
  const popoverId = useId();
  const buttonRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const updatePosition = useCallback(() => {
    if (!buttonRef.current) return;

    const triggerRect = buttonRef.current.getBoundingClientRect();

    const availableWidth = Math.max(0, window.innerWidth - 24);
    const popoverWidth = popoverRef.current ? popoverRef.current.offsetWidth : Math.min(320, availableWidth);
    const popoverHeight = popoverRef.current ? popoverRef.current.offsetHeight : 120;
    const margin = 12;

    let left = 0;
    if (align === 'left') {
      left = triggerRect.left;
    } else if (align === 'center') {
      left = triggerRect.left + (triggerRect.width / 2) - (popoverWidth / 2);
    } else {
      left = triggerRect.right - popoverWidth;
    }

    const maxLeft = Math.max(margin, window.innerWidth - popoverWidth - margin);
    left = Math.max(margin, Math.min(maxLeft, left));

    let top = 0;
    if (position === 'top') {
      top = triggerRect.top - popoverHeight - 8;
      if (top < margin) {
        top = triggerRect.bottom + 8;
      }
    } else {
      top = triggerRect.bottom + 8;
      if (top + popoverHeight > window.innerHeight - margin) {
        top = triggerRect.top - popoverHeight - 8;
      }
    }

    const maxTop = Math.max(margin, window.innerHeight - popoverHeight - margin);
    top = Math.max(margin, Math.min(maxTop, top));

    setCoords({ top, left });
  }, [align, position]);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
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
      
      updatePosition();

      window.addEventListener('scroll', updatePosition, true);
      window.addEventListener('resize', updatePosition);

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
  }, [isOpen, updatePosition]);

  useEffect(() => {
    if (isOpen) {
      updatePosition();
    }
  }, [content, isOpen, updatePosition]);

  return (
    <>
      <div id="info-popover-wrapper" className={`inline-block relative leading-none ${className}`} ref={containerRef}>
        <button
          ref={buttonRef}
          type="button"
          onClick={(event) => {
            event.preventDefault();
            event.stopPropagation();
            setIsOpen(open => !open);
          }}
          className="text-text-muted hover:text-text-primary hover:bg-surface-muted p-0.5 rounded transition-all cursor-pointer inline-flex items-center justify-center"
          title="More information"
          aria-label="More information"
          aria-expanded={isOpen}
          aria-controls={isOpen ? popoverId : undefined}
        >
          <Info aria-hidden="true" size={iconSize} />
        </button>
      </div>

      {isOpen && typeof document !== 'undefined' && createPortal(
        <div
          ref={popoverRef}
          id={popoverId}
          role="note"
          style={{
            position: 'fixed',
            top: coords ? `${coords.top}px` : '0px',
            left: coords ? `${coords.left}px` : '0px',
            opacity: coords ? 1 : 0,
            pointerEvents: coords ? 'auto' : 'none',
            maxHeight: 'calc(100vh - 24px)',
          }}
          className="z-[100] w-[calc(100vw-1.5rem)] max-w-80 overflow-y-auto rounded-xl border border-border-strong bg-surface p-3 text-left text-[11px] font-normal leading-relaxed text-text-muted shadow-lg transition-opacity duration-150 whitespace-normal"
        >
          {content}
        </div>,
        document.body,
      )}
    </>
  );
}
