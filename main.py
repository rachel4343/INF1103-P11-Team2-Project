# ==============================================
#  Phishing Detection Tool
#  INF1103 Team Project
#
#  Menu options:
#    1. Submit Email Report 
#    2. Keyword Checker Tool
#    3. Exit
#
# ==============================================

import ai_manager
import data_manager
import io_manager
import logic_manager


def handle_submit(records):
    report = io_manager.collect_report_input()
    io_manager.display_message("\n  Analysing report...")
    ai_result, ai_error = ai_manager.analyze_email(report)   # <-- fixed name

    report_id = logic_manager.next_report_id(records)
    record = logic_manager.build_final_record(report_id, report, ai_result, ai_error)

    records.append(record)
    data_manager.save_records(records)
    io_manager.display_assessment(record)
    io_manager.display_message(f"\n  Saved. Total reports: {len(records)}")


def handle_keyword_check():
    text = io_manager.collect_keyword_text()
    if not text:
        io_manager.display_message("  Nothing entered.")
        return
    result = logic_manager.scan_keywords(text)
    io_manager.display_keyword_results(result)


def main():
    records = data_manager.load_records()
    try:
        while True:
            choice = io_manager.show_main_menu()
            if choice == 1:
                handle_submit(records)
            elif choice == 2:
                handle_keyword_check()
            else:
                io_manager.display_message("\nStay safe!")
                break
    except (EOFError, KeyboardInterrupt):
        io_manager.display_message("\nInput closed. Exiting.")


if __name__ == "__main__":
    main()