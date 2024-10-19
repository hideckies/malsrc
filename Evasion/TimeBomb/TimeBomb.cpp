/*
Title: TimeBomb
Resources:
	- https://unprotect.it/technique/time-bomb/
*/
#include <Windows.h>
#include <ctime>
#include <string>
#include <sstream>
#include <stdio.h>

constexpr double timeAttackInDays = 1.0; // Replace it with the days we want to wait.

time_t TimeWhenCompiled() {
	std::string sDate = __DATE__;
	std::string sTime = __TIME__;

    // Retrive the date.
	std::istringstream issDate(sDate);
	std::string sMonth;
	int day;
	int year;
	issDate >> sMonth >> day >> year;

	int month;
	if (sMonth == "Jan") month = 1;
	else if (sMonth == "Feb") month = 2;
	else if (sMonth == "Mar") month = 3;
	else if (sMonth == "Apr") month = 4;
	else if (sMonth == "May") month = 5;
	else if (sMonth == "Jun") month = 6;
	else if (sMonth == "Jul") month = 7;
	else if (sMonth == "Aug") month = 8;
	else if (sMonth == "Sep") month = 9;
	else if (sMonth == "Oct") month = 10;
	else if (sMonth == "Nov") month = 11;
	else if (sMonth == "Dec") month = 12;
	else exit(-1);

    // Retrieve the time.
	for (std::string::size_type pos = sTime.find(':'); pos != std::string::npos; pos = sTime.find(':', pos)) {
		sTime[pos] = ' ';
	}
	std::istringstream iss_time(sTime);
	int hour, min, sec;
	iss_time >> hour >> min >> sec;

    // Put them together.
	tm t = { 0 };
	t.tm_mon = month - 1;
	t.tm_mday = day;
	t.tm_year = year - 1900;
	t.tm_hour = hour;
	t.tm_min = min;
	t.tm_sec = sec;

	return mktime(&t);
}

VOID TimeBomb() {
	time_t tCurrentTime = time(nullptr);
	time_t tBuildTime = TimeWhenCompiled();

	double elapsedTime = difftime(tCurrentTime, tBuildTime);
	const double timeToWait = timeAttackInDays * 24.0 * 60.0 * 60.0;

	if (elapsedTime <= timeToWait) {
		printf("Wait until the time is right.\n");
		exit(-1);
	}
}
