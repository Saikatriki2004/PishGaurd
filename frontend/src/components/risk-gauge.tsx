"use client"

import { RadialBar, RadialBarChart, PolarAngleAxis, ResponsiveContainer } from "recharts"

interface RiskGaugeProps {
    score: number
    level: string
}

export function RiskGauge({ score, level }: RiskGaugeProps) {
    const data = [{ name: "Risk", value: score, fill: getColor(score) }]

    function getColor(score: number) {
        if (score >= 85) return "#ef4444" // red-500
        if (score >= 55) return "#eab308" // yellow-500
        return "#22c55e" // green-500
    }

    return (
        <div className="relative h-[160px] w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
                <RadialBarChart
                    cx="50%"
                    cy="50%"
                    innerRadius="70%"
                    outerRadius="100%"
                    barSize={15}
                    data={data}
                    startAngle={180}
                    endAngle={0}
                >
                    <PolarAngleAxis
                        type="number"
                        domain={[0, 100]}
                        angleAxisId={0}
                        tick={false}
                    />
                    <RadialBar
                        background
                        dataKey="value"
                        cornerRadius={30}
                        className="stroke-transparent"
                    />
                </RadialBarChart>
            </ResponsiveContainer>

            {/* Centered Text */}
            <div className="absolute top-[45%] left-1/2 -translate-x-1/2 -translate-y-1/2 text-center">
                <div className="flex items-baseline justify-center gap-1">
                    <span className="text-4xl font-bold text-slate-900 dark:text-white">{score}</span>
                    <span className="text-sm text-slate-500">/ 100</span>
                </div>
            </div>
        </div>
    )
}
