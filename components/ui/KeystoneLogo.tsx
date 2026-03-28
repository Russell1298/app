import Svg, { Path, Defs, LinearGradient, Stop } from "react-native-svg";

interface Props {
  size?: number;
  light?: boolean; // white version for use on blue backgrounds
}

export function KeystoneLogo({ size = 64, light = false }: Props) {
  const fillColor = light ? "rgba(255,255,255,0.92)" : undefined;

  return (
    <Svg width={size} height={size * 0.56} viewBox="0 0 100 56">
      {!light && (
        <Defs>
          <LinearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="0%">
            <Stop offset="0%" stopColor="#1a6fd4" />
            <Stop offset="50%" stopColor="#4da3ff" />
            <Stop offset="100%" stopColor="#1a6fd4" />
          </LinearGradient>
        </Defs>
      )}
      {/* Left segment */}
      <Path
        d="M 5 54 A 46 46 0 0 1 18 20 L 22 25 A 38 38 0 0 0 11 54 Z"
        fill={light ? fillColor : "url(#grad)"}
      />
      {/* Second segment */}
      <Path
        d="M 20 18 A 46 46 0 0 1 34 8 L 36 14 A 38 38 0 0 0 24 23 Z"
        fill={light ? fillColor : "url(#grad)"}
      />
      {/* Center segment */}
      <Path
        d="M 36 6 A 46 46 0 0 1 64 6 L 62 12 A 38 38 0 0 0 38 12 Z"
        fill={light ? fillColor : "url(#grad)"}
      />
      {/* Fourth segment */}
      <Path
        d="M 66 8 A 46 46 0 0 1 80 18 L 76 23 A 38 38 0 0 0 64 14 Z"
        fill={light ? fillColor : "url(#grad)"}
      />
      {/* Right segment */}
      <Path
        d="M 82 20 A 46 46 0 0 1 95 54 L 89 54 A 38 38 0 0 0 78 25 Z"
        fill={light ? fillColor : "url(#grad)"}
      />
    </Svg>
  );
}
