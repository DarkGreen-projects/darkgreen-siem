type Props = {
  text: string;
  /** Glyph inside the tip circle. Default: i */
  icon?: string;
};

/** Small hover/focus tooltip (i / ?). */
export default function InfoTip({ text, icon = "i" }: Props) {
  return (
    <span className="info-tip" tabIndex={0} aria-label={text}>
      <span className="info-tip-icon" aria-hidden>
        {icon}
      </span>
      <span className="info-tip-bubble" role="tooltip">
        {text}
      </span>
    </span>
  );
}
