#include "pch.h"
#include "CppUnitTest.h"

#include "process_enumerator.hpp"
#include "process_scanner.hpp"

#include "blocking_apc.cpp"
#include "blocking_timer.cpp"
#include "suspicious_timer.cpp"
#include "abnormal_intermodular_call.cpp"
#include "hardware_breakpoints.cpp"
#include "private_memory.cpp"
#include "return_address_spoofing.cpp"
#include "stomped_module.cpp"
#include "non_executable_memory.cpp"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace hsb;

namespace HSBUnittests
{

	extern "C" DWORD64 getgadget(void);

	void blocking_function(void) {

		DWORD64 actualAddress = getgadget();
		void** pvAddressOfReturnAddress = (void**) _AddressOfReturnAddress();
		*pvAddressOfReturnAddress = (void*)actualAddress;

		Sleep(1000 * 60 * 60);

	}

	void queue_blocking_timers(void){

		HANDLE  hTimerQueue = NULL;
		HANDLE  hNewTimer   = NULL, hNewTimer2 = NULL;

		DWORD sleeptime = 1000 * 60 * 60;

		hTimerQueue = CreateTimerQueue();

		CreateTimerQueueTimer(&hNewTimer,hTimerQueue,(WAITORTIMERCALLBACK) blocking_function, NULL,0,0,WT_EXECUTELONGFUNCTION);
		CreateTimerQueueTimer(&hNewTimer2,hTimerQueue,(WAITORTIMERCALLBACK)Sleep,(PVOID)&sleeptime,0,0,WT_EXECUTELONGFUNCTION);

	}

	void queue_future_timer(void){
		HANDLE  hTimerQueue = NULL;
		HANDLE  hNewTimer   = NULL;

		PVOID pNtContinue = NULL;
		pNtContinue = GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtContinue");

		hTimerQueue = CreateTimerQueue();
		CreateTimerQueueTimer(&hNewTimer,hTimerQueue,(WAITORTIMERCALLBACK)pNtContinue,NULL,1000 * 60,0,WT_EXECUTEINTIMERTHREAD);
	}

	void queue_blocking_apc(void) {
		HANDLE h_thread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)queue_blocking_apc,NULL,CREATE_SUSPENDED,NULL);
		QueueUserAPC((PAPCFUNC)blocking_function,h_thread,NULL);
		ResumeThread(h_thread);
	}

	void exec_msgbox_shellcode(void) {

		//msgbox
		unsigned char data[] ={0x56,0x48,0x89,0xe6,0x48,0x83,0xe4,0xf0,0x48,0x83,0xec,0x20,0xe8,0x7f,0x01,0x00,0x00,0x48,0x89,0xf4,0x5e,0xc3,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,0x65,0x48,0x8b,0x04,0x25,0x60,0x00,0x00,0x00,0x48,0x8b,0x40,0x18,0x41,0x89,0xca,0x4c,0x8b,0x58,0x20,0x4d,0x89,0xd9,0x66,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,0x49,0x8b,0x49,0x50,0x48,0x85,0xc9,0x74,0x63,0x0f,0xb7,0x01,0x66,0x85,0xc0,0x74,0x5f,0x48,0x89,0xca,0x0f,0x1f,0x40,0x00,0x44,0x8d,0x40,0xbf,0x66,0x41,0x83,0xf8,0x19,0x77,0x06,0x83,0xc0,0x20,0x66,0x89,0x02,0x0f,0xb7,0x42,0x02,0x48,0x83,0xc2,0x02,0x66,0x85,0xc0,0x75,0xe2,0x0f,0xb7,0x01,0x66,0x85,0xc0,0x74,0x32,0x41,0xb8,0x05,0x15,0x00,0x00,0x0f,0x1f,0x40,0x00,0x44,0x89,0xc2,0x48,0x83,0xc1,0x02,0xc1,0xe2,0x05,0x01,0xd0,0x41,0x01,0xc0,0x0f,0xb7,0x01,0x66,0x85,0xc0,0x75,0xe9,0x45,0x39,0xc2,0x74,0x17,0x4d,0x8b,0x09,0x4d,0x39,0xcb,0x75,0x94,0x31,0xc0,0xc3,0x90,0x41,0xb8,0x05,0x15,0x00,0x00,0x45,0x39,0xc2,0x75,0xe9,0x49,0x8b,0x41,0x20,0xc3,0x41,0x54,0x41,0x89,0xd4,0x53,0x89,0xcb,0x48,0x83,0xec,0x38,0xe8,0x4f,0xff,0xff,0xff,0x48,0x85,0xc0,0x75,0x22,0xb9,0x75,0xee,0x40,0x70,0xe8,0x40,0xff,0xff,0xff,0x48,0x89,0xc1,0x48,0x85,0xc0,0x75,0x28,0x48,0x83,0xc4,0x38,0x31,0xc0,0x5b,0x41,0x5c,0xc3,0x66,0x0f,0x1f,0x44,0x00,0x00,0x48,0x89,0xc1,0x48,0x83,0xc4,0x38,0x44,0x89,0xe2,0x5b,0x41,0x5c,0xe9,0xd6,0x00,0x00,0x00,0x66,0x0f,0x1f,0x44,0x00,0x00,0xba,0xfb,0xf0,0xbf,0x5f,0xe8,0xc6,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0xc9,0x81,0xfb,0xf3,0xd3,0x6b,0x5a,0x74,0x31,0x81,0xfb,0x6d,0x9c,0xbd,0x8d,0x75,0xb9,0x48,0xbb,0x57,0x69,0x6e,0x69,0x6e,0x65,0x74,0x2e,0x48,0x8d,0x4c,0x24,0x24,0xc7,0x44,0x24,0x2c,0x64,0x6c,0x6c,0x00,0x48,0x89,0x5c,0x24,0x24,0xff,0xd0,0x48,0x89,0xc1,0xeb,0x2e,0x66,0x0f,0x1f,0x44,0x00,0x00,0xba,0x6c,0x6c,0x00,0x00,0x48,0x8d,0x4c,0x24,0x24,0xc6,0x44,0x24,0x2e,0x00,0x48,0xbb,0x55,0x73,0x65,0x72,0x33,0x32,0x2e,0x64,0x48,0x89,0x5c,0x24,0x24,0x66,0x89,0x54,0x24,0x2c,0xff,0xd0,0x48,0x89,0xc1,0x48,0x85,0xc9,0x0f,0x85,0x72,0xff,0xff,0xff,0xe9,0x5a,0xff,0xff,0xff,0x90,0x90,0x48,0x83,0xec,0x38,0xba,0xb4,0x14,0x4f,0x38,0xb9,0xf3,0xd3,0x6b,0x5a,0xe8,0x1d,0xff,0xff,0xff,0x45,0x31,0xc0,0x48,0x85,0xc0,0x74,0x25,0x48,0x8d,0x54,0x24,0x2b,0xc7,0x44,0x24,0x2b,0x4d,0x6f,0x69,0x6e,0x41,0xb9,0x01,0x00,0x00,0x00,0x31,0xc9,0x49,0x89,0xd0,0xc6,0x44,0x24,0x2f,0x00,0xff,0xd0,0x41,0xb8,0x01,0x00,0x00,0x00,0x44,0x89,0xc0,0x48,0x83,0xc4,0x38,0xc3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x57,0x56,0x53,0x48,0x63,0x41,0x3c,0x8b,0xbc,0x01,0x88,0x00,0x00,0x00,0x48,0x01,0xcf,0x44,0x8b,0x4f,0x20,0x8b,0x5f,0x18,0x49,0x01,0xc9,0x85,0xdb,0x74,0x59,0x49,0x89,0xcb,0x89,0xd6,0x45,0x31,0xd2,0x66,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,0x41,0x8b,0x01,0xb9,0x05,0x15,0x00,0x00,0x4c,0x01,0xd8,0x4c,0x8d,0x40,0x01,0x0f,0xb6,0x00,0x84,0xc0,0x74,0x21,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,0x89,0xca,0xc1,0xe2,0x05,0x01,0xd0,0x01,0xc1,0x4c,0x89,0xc0,0x49,0x83,0xc0,0x01,0x0f,0xb6,0x00,0x84,0xc0,0x75,0xe9,0x39,0xce,0x74,0x13,0x49,0x83,0xc2,0x01,0x49,0x83,0xc1,0x04,0x4c,0x39,0xd3,0x75,0xb8,0x5b,0x31,0xc0,0x5e,0x5f,0xc3,0x8b,0x57,0x24,0x4b,0x8d,0x0c,0x53,0x8b,0x47,0x1c,0x5b,0x5e,0x0f,0xb7,0x14,0x11,0x5f,0x49,0x8d,0x14,0x93,0x8b,0x04,0x02,0x4c,0x01,0xd8,0xc3,0x90,0x90,0x90,0x90,0x90,0x90,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		unsigned int data_size = sizeof(data);

		PVOID pBuffer = VirtualAlloc(0,2048,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
		memcpy(pBuffer,data,data_size);
		CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)pBuffer,NULL,0,NULL);

	}

	void thread_with_hw_br(void) {

		DWORD tid = 0;
		CONTEXT context ={0};
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		HANDLE hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)blocking_function,NULL,CREATE_SUSPENDED,&tid);
		if(!GetThreadContext(hThread,&context)) {
			return;
		}

		context.Dr0 = (DWORD_PTR)blocking_function;
		context.Dr1 = (DWORD_PTR)blocking_function;
		context.Dr2 = (DWORD_PTR)blocking_function;
		context.Dr3 = (DWORD_PTR)blocking_function;
		context.Dr7 |= (1 << 0);
		context.Dr7 &= ~(1 << 16);
		context.Dr7 &= ~(1 << 17);

		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if(!SetThreadContext(hThread,&context)) {
			return;
		}

	}

	TEST_CLASS(scan_tests)
	{
	public:

		using process_enumerator = hsb::containers::process_enumerator;
		using process_scanner = hsb::scanning::process_scanner;
		using process = hsb::containers::process;

		scan_tests() {
			exec_msgbox_shellcode();
			queue_blocking_apc();
			thread_with_hw_br();
			queue_blocking_timers();
			queue_future_timer();
		}

		~scan_tests() {	}

		TEST_METHOD(future_timer)
		{

			process_enumerator process_enumerator((uint16_t)GetCurrentProcessId(),false);
			process_scanner process_scanner;
			std::vector<std::unique_ptr<process>> processes;

			processes = process_enumerator.enumerate_processes();
			Assert::AreEqual((int)processes.size(),1);

			hsb::scanning::process_scans::suspicious_timer(processes[0].get());

			Assert::AreNotEqual((int)processes[0]->detections.size(),0);
		}

		TEST_METHOD(blocking_apc)
		{

			process_enumerator process_enumerator((uint16_t)GetCurrentProcessId(), false);
			process_scanner process_scanner;
			std::vector<std::unique_ptr<process>> processes;

			processes = process_enumerator.enumerate_processes();
			Assert::AreEqual((int)processes.size(), 1);

			for (auto& thread : processes[0]->threads) {
				hsb::scanning::thread_scans::blocking_apc(processes[0].get(), thread.get());
			}

			Assert::AreNotEqual((int)processes[0]->detections.size(),0);

		}

		TEST_METHOD(blocking_timer)
		{

			process_enumerator process_enumerator((uint16_t)GetCurrentProcessId(), false);
			process_scanner process_scanner;
			std::vector<std::unique_ptr<process>> processes;

			processes = process_enumerator.enumerate_processes();
			Assert::AreEqual((int)processes.size(), 1);

			for (auto& thread : processes[0]->threads) {
				hsb::scanning::thread_scans::blocking_timer(processes[0].get(), thread.get());
			}

			Assert::AreNotEqual((int)processes[0]->detections.size(), 0);
		}

		TEST_METHOD(private_memory)
		{

			process_enumerator process_enumerator((uint16_t)GetCurrentProcessId(), false);
			process_scanner process_scanner;
			std::vector<std::unique_ptr<process>> processes;

			processes = process_enumerator.enumerate_processes();
			Assert::AreEqual((int)processes.size(), 1);

			for (auto& thread : processes[0]->threads) {
				hsb::scanning::thread_scans::private_memory(processes[0].get(), thread.get());
			}

			Assert::AreNotEqual((int)processes[0]->detections.size(), 0);
		}

		TEST_METHOD(hw_breakpoints)
		{

			process_enumerator process_enumerator((uint16_t)GetCurrentProcessId(), false);
			process_scanner process_scanner;
			std::vector<std::unique_ptr<process>> processes;

			processes = process_enumerator.enumerate_processes();
			Assert::AreEqual((int)processes.size(), 1);

			for (auto& thread : processes[0]->threads) {
				hsb::scanning::thread_scans::hardware_breakpoints(processes[0].get(), thread.get());
			}

			Assert::AreNotEqual((int)processes[0]->detections.size(), 0);
		}

		TEST_METHOD(intermodular_call)
		{

			process_enumerator process_enumerator((uint16_t)GetCurrentProcessId(),false);
			process_scanner process_scanner;
			std::vector<std::unique_ptr<process>> processes;

			processes = process_enumerator.enumerate_processes();
			Assert::AreEqual((int)processes.size(),1);

			for(auto& thread : processes[0]->threads) {
				hsb::scanning::thread_scans::abnormal_intermodular_call(processes[0].get(),thread.get());
			}

			Assert::AreNotEqual((int)processes[0]->detections.size(),0);
		}
	
		TEST_METHOD(stomped_module)
		{

			process_enumerator process_enumerator((uint16_t)GetCurrentProcessId(),false);
			process_scanner process_scanner;
			std::vector<std::unique_ptr<process>> processes;

			processes = process_enumerator.enumerate_processes();
			Assert::AreEqual((int)processes.size(),1);

			for(auto& thread : processes[0]->threads) {
				hsb::scanning::thread_scans::stomped_module(processes[0].get(),thread.get());
			}

			Assert::AreNotEqual((int)processes[0]->detections.size(),0);
		}

		TEST_METHOD(non_executable_memory)
		{

			process_enumerator process_enumerator((uint16_t)GetCurrentProcessId(),false);
			process_scanner process_scanner;
			std::vector<std::unique_ptr<process>> processes;

			processes = process_enumerator.enumerate_processes();
			Assert::AreEqual((int)processes.size(),1);

			for(auto& thread : processes[0]->threads) {
				hsb::scanning::thread_scans::non_executable_memory(processes[0].get(),thread.get());
			}

			Assert::AreNotEqual((int)processes[0]->detections.size(),0);
		}

		TEST_METHOD(return_addr_spoofing)
		{

			process_enumerator process_enumerator((uint16_t)GetCurrentProcessId(),false);
			process_scanner process_scanner;
			std::vector<std::unique_ptr<process>> processes;

			processes = process_enumerator.enumerate_processes();
			Assert::AreEqual((int)processes.size(),1);

			for(auto& thread : processes[0]->threads) {
				hsb::scanning::thread_scans::return_address_spoofing(processes[0].get(),thread.get());
			}

			Assert::AreNotEqual((int)processes[0]->detections.size(),0);
		}

	};
}
