import React from "react";
import { Box, Typography } from "@mui/material";
import { Gauge } from "@mui/x-charts/Gauge";

const getGaugeColor = (points) => {
  if (points >= 75) return "#4caf50";
  if (points >= 40) return "#ff9800";
  return "#f44336";
};

const SemiCircularGauge = ({ points }) => {
  points = 2;

  return (
    <Gauge
      width={100}
      height={100}
      value={points}
      startAngle={-90}
      endAngle={90}
      sx={{
        [`& .MuiGauge-valueArc`]: {
          fill: getGaugeColor(points), // green
        },
      }}
    />
  );
};

export default SemiCircularGauge;
