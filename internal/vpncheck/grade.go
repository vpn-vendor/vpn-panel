package vpncheck

import "fmt"

const (
	gradeTargetLossPct = 0.5
	gradeTargetJitter  = 20.0
	gradeTargetOneWay  = 100.0

	gradeOKLossPct = 1.0
	gradeOKJitter  = 30.0
	gradeOKOneWay  = 150.0
)

type Grade string

const (
	GradeTarget  Grade = "цель"
	GradeOK      Grade = "приемлемо"
	GradeBad     Grade = "разговор рвётся"
	GradeUnknown Grade = "не измерено"

	GradeThrough Grade = "проходят"
	GradeBlocked Grade = "не проходят"
)

func GradeVoice(s Stats) (Grade, string) {
	if s.Sent == 0 {
		return GradeUnknown, "измерить не удалось"
	}
	oneWay := s.AvgMs / 2
	switch {
	case s.LossPct <= gradeTargetLossPct && s.JitterMs <= gradeTargetJitter && oneWay <= gradeTargetOneWay:
		return GradeTarget, fmt.Sprintf(
			"потери %.2f %%, джиттер %.1f мс, задержка в одну сторону около %.0f мс — как у оператора связи",
			s.LossPct, s.JitterMs, oneWay)
	case s.LossPct <= gradeOKLossPct && s.JitterMs <= gradeOKJitter && oneWay <= gradeOKOneWay:
		return GradeOK, fmt.Sprintf(
			"потери %.2f %%, джиттер %.1f мс, задержка в одну сторону около %.0f мс — разговор идёт без жалоб",
			s.LossPct, s.JitterMs, oneWay)
	default:
		return GradeBad, fmt.Sprintf(
			"потери %.2f %%, джиттер %.1f мс, задержка в одну сторону около %.0f мс",
			s.LossPct, s.JitterMs, oneWay)
	}
}

func BurstNote(s Stats) string {
	switch {
	case s.Sent == 0 || s.Received == s.Sent:
		return ""
	case s.BurstEvents == 0:
		return "потери одиночные — такие кодек прячет, на слух они почти незаметны"
	default:
		return fmt.Sprintf("потери идут пачками (%d случаев, самая длинная — %d подряд) — это слышно как провалы в речи",
			s.BurstEvents, s.MaxBurst)
	}
}

func GradeProbe(k Kind, s Stats) (Grade, string) {
	if k != KindSize {
		return GradeVoice(s)
	}
	switch {
	case s.Sent == 0:
		return GradeUnknown, "измерить не удалось"
	case s.LossPct >= 80:
		return GradeBlocked, "крупные пакеты по пути не проходят — сайты будут открываться и виснуть"
	case s.LossPct > 0:
		return GradeThrough, fmt.Sprintf("проходят, но теряются на %.0f %%", s.LossPct)
	default:
		return GradeThrough, "проходят полностью"
	}
}
