type Props = {
  text: string;
};

/** Small (i) hover tooltip. */
export default function InfoTip({ text }: Props) {
  return (
    <span className="info-tip" tabIndex={0} aria-label={text}>
      <span className="info-tip-icon" aria-hidden>
        i
      </span>
      <span className="info-tip-bubble" role="tooltip">
        {text}
      </span>
    </span>
  );
}
